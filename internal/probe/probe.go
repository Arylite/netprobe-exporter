package probe

import (
	"errors"
	"math"
	"net"
	"strconv"
	"syscall"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	"github.com/Arylite/netprobe-exporter/internal/config"
)

// interSample is the delay between the samples of a single cycle.
const interSample = 100 * time.Millisecond

// Result holds the samples of one probing cycle against one target.
type Result struct {
	Sent, Received        int
	Min, Avg, Max, StdDev time.Duration
	RTTs                  []time.Duration // every sample that came back, in order
	Err                   error           // last sample error, for logging
}

// Prober runs one probing cycle against a host.
type Prober interface {
	// Probe sends count samples to host and reports the timings. The host is
	// a literal address: the worker resolves the name once per cycle and hands
	// the result down, so a cycle costs one lookup instead of one per sample.
	Probe(host string, count int, timeout time.Duration) Result
}

// New builds the prober for one configured probe of one target.
func New(p config.Probe, t config.Target, privileged bool) Prober {
	switch p.Proto {
	case "icmp":
		return icmpProber{privileged: privileged}
	case "tcp":
		return tcpProber{port: p.Port, local: localAddr(p.Proto, p.LocalPort)}
	case "udp":
		return udpProber{port: p.Port, local: localAddr(p.Proto, p.LocalPort), payload: t.PayloadBytes}
	}
	panic("unreachable: config.ParseProbe rejects unknown protocols")
}

// localAddr is the source address a probe binds to, nil for an ephemeral port.
// Pinning it lets a firewall or an ACL on the far side match the probe.
//
// ponytail: no SO_REUSEADDR. Samples close with RST and so leave no TIME_WAIT,
// which keeps the port free for the next one; add a Dialer.Control hook if a
// rebind ever fails.
func localAddr(proto string, port int) net.Addr {
	if port == 0 {
		return nil
	}
	if proto == "udp" {
		return &net.UDPAddr{Port: port}
	}
	return &net.TCPAddr{Port: port}
}

// ICMP

type icmpProber struct{ privileged bool }

func (p icmpProber) Probe(host string, count int, timeout time.Duration) Result {
	r := Result{Sent: count}
	pinger, err := probing.NewPinger(host)
	if err != nil {
		r.Err = err
		return r
	}
	pinger.Count = count
	pinger.Interval = interSample
	pinger.Timeout = timeout + interSample*time.Duration(count)
	pinger.RecordRtts = true // the per-sample series feeds the histogram and the jitter
	pinger.SetPrivileged(p.privileged)

	if err := pinger.Run(); err != nil {
		r.Err = err
		return r
	}
	s := pinger.Statistics()
	// summarize rather than the pinger's own statistics, so that the three
	// protocols report figures computed the same way.
	r.summarize(s.Rtts)
	r.Sent = s.PacketsSent
	return r
}

// TCP

type tcpProber struct {
	port  int
	local net.Addr
}

func (p tcpProber) Probe(host string, count int, timeout time.Duration) Result {
	addr := net.JoinHostPort(host, strconv.Itoa(p.port))
	r := Result{Sent: count}
	rtts := make([]time.Duration, 0, count)
	for i := 0; i < count; i++ {
		if i > 0 {
			time.Sleep(interSample)
		}
		d, err := tcpRTT(addr, p.local, timeout)
		if err != nil {
			r.Err = err
			continue
		}
		rtts = append(rtts, d)
	}
	r.summarize(rtts)
	return r
}

// tcpRTT measures the SYN to SYN-ACK delta: DialTimeout returns once connect(2)
// completes, which happens when the SYN-ACK is received. The measurement carries
// a few hundred microseconds of scheduler overhead and completes the handshake,
// which is accurate enough for path monitoring but not for sub-millisecond work.
func tcpRTT(addr string, local net.Addr, timeout time.Duration) (time.Duration, error) {
	dialer := net.Dialer{Timeout: timeout, LocalAddr: local}
	start := time.Now()
	conn, err := dialer.Dial("tcp", addr)
	d := time.Since(start)
	if err != nil {
		return 0, err
	}
	// Close with RST rather than FIN to avoid accumulating TIME_WAIT sockets.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	conn.Close()
	return d, nil
}

// UDP

type udpProber struct {
	port    int
	local   net.Addr
	payload []byte
}

func (p udpProber) Probe(host string, count int, timeout time.Duration) Result {
	addr := net.JoinHostPort(host, strconv.Itoa(p.port))
	r := Result{Sent: count}
	rtts := make([]time.Duration, 0, count)
	for i := 0; i < count; i++ {
		if i > 0 {
			time.Sleep(interSample)
		}
		d, err := udpRTT(addr, p.local, p.payload, timeout)
		if err != nil {
			r.Err = err
			continue
		}
		rtts = append(rtts, d)
	}
	r.summarize(rtts)
	return r
}

// udpRTT sends one datagram and waits for either an application reply or the
// ICMP port unreachable message, which the kernel reports as ECONNREFUSED on a
// connected UDP socket. Both outcomes prove the host was reached and are counted
// as a success; only a timeout counts as a loss. This needs no raw socket and no
// additional capability.
func udpRTT(addr string, local net.Addr, payload []byte, timeout time.Duration) (time.Duration, error) {
	dialer := net.Dialer{Timeout: timeout, LocalAddr: local}
	conn, err := dialer.Dial("udp", addr) // binds, sends nothing
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return 0, err
	}
	_ = conn.SetReadDeadline(start.Add(timeout))
	_, err = conn.Read(make([]byte, 1500))
	d := time.Since(start)

	if err == nil || errors.Is(err, syscall.ECONNREFUSED) {
		return d, nil
	}
	return 0, err
}

func (r *Result) summarize(rtts []time.Duration) {
	r.Received = len(rtts)
	r.RTTs = rtts
	if len(rtts) == 0 {
		return
	}
	r.Min, r.Max = rtts[0], rtts[0]
	var sum time.Duration
	for _, d := range rtts {
		if d < r.Min {
			r.Min = d
		}
		if d > r.Max {
			r.Max = d
		}
		sum += d
	}
	r.Avg = sum / time.Duration(len(rtts))

	var sq float64
	for _, d := range rtts {
		diff := float64(d - r.Avg)
		sq += diff * diff
	}
	r.StdDev = time.Duration(math.Sqrt(sq / float64(len(rtts))))
}
