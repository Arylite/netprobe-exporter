package main

import (
	"errors"
	"math"
	"net"
	"strconv"
	"syscall"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// interSample is the delay between the samples of a single cycle.
const interSample = 100 * time.Millisecond

// Result holds the aggregated samples of one probing cycle against one target.
type Result struct {
	Sent, Received        int
	Min, Avg, Max, StdDev time.Duration
	IP                    string // address that was actually probed
	Err                   error  // last sample error, for logging
}

// Prober runs one probing cycle against a host.
type Prober interface {
	// Probe sends count samples to host and reports the aggregated timings.
	// The host is passed on every call so that names are resolved each cycle.
	Probe(host string, count int, timeout time.Duration) Result
}

func newProber(p Probe, t Target, privileged bool) Prober {
	switch p.Proto {
	case "icmp":
		return icmpProber{privileged: privileged}
	case "tcp":
		return tcpProber{port: p.Port}
	case "udp":
		return udpProber{port: p.Port, payload: t.payload}
	}
	panic("unreachable: parseProbe rejects unknown protocols")
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
	pinger.SetPrivileged(p.privileged)

	if err := pinger.Run(); err != nil {
		r.Err = err
		return r
	}
	s := pinger.Statistics()
	r.Sent, r.Received = s.PacketsSent, s.PacketsRecv
	if s.IPAddr != nil {
		r.IP = s.IPAddr.String()
	}
	if r.Received == 0 {
		return r
	}
	r.Min, r.Avg, r.Max, r.StdDev = s.MinRtt, s.AvgRtt, s.MaxRtt, s.StdDevRtt
	return r
}

// TCP

type tcpProber struct{ port int }

func (p tcpProber) Probe(host string, count int, timeout time.Duration) Result {
	addr := net.JoinHostPort(host, strconv.Itoa(p.port))
	r := Result{Sent: count}
	rtts := make([]time.Duration, 0, count)
	for i := 0; i < count; i++ {
		if i > 0 {
			time.Sleep(interSample)
		}
		d, ip, err := tcpRTT(addr, timeout)
		if err != nil {
			r.Err = err
			continue
		}
		if r.IP == "" {
			r.IP = ip
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
func tcpRTT(addr string, timeout time.Duration) (time.Duration, string, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	d := time.Since(start)
	if err != nil {
		return 0, "", err
	}
	// Close with RST rather than FIN to avoid accumulating TIME_WAIT sockets.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	ip := hostOf(conn.RemoteAddr())
	conn.Close()
	return d, ip, nil
}

// UDP

type udpProber struct {
	port    int
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
		d, ip, err := udpRTT(addr, p.payload, timeout)
		if ip != "" && r.IP == "" {
			r.IP = ip
		}
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
func udpRTT(addr string, payload []byte, timeout time.Duration) (time.Duration, string, error) {
	conn, err := net.DialTimeout("udp", addr, timeout) // resolves, sends nothing
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	ip := hostOf(conn.RemoteAddr())

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return 0, ip, err
	}
	_ = conn.SetReadDeadline(start.Add(timeout))
	_, err = conn.Read(make([]byte, 1500))
	d := time.Since(start)

	if err == nil || errors.Is(err, syscall.ECONNREFUSED) {
		return d, ip, nil
	}
	return 0, ip, err
}

func (r *Result) summarize(rtts []time.Duration) {
	r.Received = len(rtts)
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

func hostOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}
