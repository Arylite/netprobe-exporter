package probe

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/Arylite/netprobe-exporter/internal/config"
)

func TestTCPProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p := New(mustProbe(t, "tcp:"+port), config.Target{}, false)

	r := p.Probe("127.0.0.1", 3, time.Second)
	if r.Received != 3 || r.Sent != 3 {
		t.Fatalf("open port: sent=%d received=%d err=%v", r.Sent, r.Received, r.Err)
	}
	if r.Min > r.Avg || r.Avg > r.Max {
		t.Fatalf("inconsistent rtt statistics: %+v", r)
	}
	// The per-sample series is what feeds the histogram and the jitter.
	if len(r.RTTs) != 3 {
		t.Fatalf("per-sample rtts = %v, want 3", r.RTTs)
	}

	// A refused connection counts as a loss for TCP.
	ln.Close()
	if r := p.Probe("127.0.0.1", 2, time.Second); r.Received != 0 {
		t.Fatalf("closed port: received=%d, want 0", r.Received)
	}
}

// A pinned local port must be the one the far side sees as the source.
func TestTCPProbeLocalPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, port, _ := net.SplitHostPort(c.RemoteAddr().String())
		seen <- port
		c.Close()
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	local := freePort(t)
	p := New(mustProbe(t, "tcp:"+port+":"+local), config.Target{}, false)

	if r := p.Probe("127.0.0.1", 1, time.Second); r.Received != 1 {
		t.Fatalf("pinned source port: received=%d err=%v", r.Received, r.Err)
	}
	select {
	case got := <-seen:
		if got != local {
			t.Fatalf("source port = %s, want %s", got, local)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no connection accepted")
	}
}

func TestUDPProbeReply(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()

	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	p := New(mustProbe(t, "udp:"+port), config.Target{PayloadBytes: []byte("ping")}, false)

	r := p.Probe("127.0.0.1", 3, time.Second)
	if r.Received != 3 {
		t.Fatalf("echo server: received=%d err=%v", r.Received, r.Err)
	}
	// A loopback round trip can complete inside one tick of the platform
	// clock, so zero is a legitimate sample here and only the ordering of the
	// statistics is worth asserting.
	if len(r.RTTs) != 3 || r.Min > r.Avg || r.Avg > r.Max {
		t.Fatalf("inconsistent rtt statistics: %+v", r)
	}
}

// A closed UDP port must read as reachable through the ICMP port unreachable
// message the kernel reports as ECONNREFUSED. A single sample is used on
// purpose: Linux rate-limits ICMP unreachables to roughly one per second, so a
// multi-sample cycle would report phantom loss.
//
// Only Unix kernels surface that message on a connected UDP socket. Windows
// swallows it, so the probe there reads a closed port as loss; the shipped
// image is Linux, which is where the behaviour has to hold.
func TestUDPProbeClosedPortIsReachable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not report ICMP port unreachable as ECONNREFUSED")
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()

	if _, err := udpRTT(addr, nil, []byte{0}, time.Second); err != nil {
		t.Fatalf("closed port should be reachable, got %v", err)
	}
}

func TestUDPProbeBlackholeIsLoss(t *testing.T) {
	// 203.0.113.0/24 is TEST-NET-3: routable in form, never answers.
	d, err := udpRTT("203.0.113.1:9", nil, []byte{0}, 300*time.Millisecond)
	if err == nil {
		t.Fatalf("blackhole should time out, got rtt=%v", d)
	}
}

func TestSummarize(t *testing.T) {
	var r Result
	r.summarize([]time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond})
	if r.Received != 3 || r.Min != 10*time.Millisecond || r.Max != 30*time.Millisecond || r.Avg != 20*time.Millisecond {
		t.Fatalf("%+v", r)
	}
	// Population standard deviation of {10, 20, 30} ms is sqrt(200/3) ms.
	if r.StdDev < 8100*time.Microsecond || r.StdDev > 8200*time.Microsecond {
		t.Fatalf("stddev = %v", r.StdDev)
	}

	var empty Result
	empty.summarize(nil)
	if empty.Received != 0 || empty.Avg != 0 {
		t.Fatalf("%+v", empty)
	}
}

// freePort returns a port that is free right now. Racy in principle, good
// enough to hand to a single dial in a single test process.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func mustProbe(t *testing.T, s string) config.Probe {
	t.Helper()
	p, err := config.ParseProbe(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
