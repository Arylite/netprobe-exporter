package main

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestParseProbe(t *testing.T) {
	ok := map[string]Probe{
		"icmp":         {Proto: "icmp"},
		"tcp:443":      {Proto: "tcp", Port: 443},
		"udp:53":       {Proto: "udp", Port: 53},
		"TCP:22":       {Proto: "tcp", Port: 22},
		" icmp ":       {Proto: "icmp"},
		"tcp:65535":    {Proto: "tcp", Port: 65535},
		"tcp:443:5000": {Proto: "tcp", Port: 443, LocalPort: 5000},
		"udp:53:5353":  {Proto: "udp", Port: 53, LocalPort: 5353},
	}
	for in, want := range ok {
		got, err := parseProbe(in)
		if err != nil {
			t.Fatalf("parseProbe(%q): unexpected error %v", in, err)
		}
		if got != want {
			t.Fatalf("parseProbe(%q) = %+v, want %+v", in, got, want)
		}
	}

	for _, in := range []string{
		"tcp", "tcp:", "tcp:0", "tcp:99999", "tcp:https", "icmp:1", "sctp:80", "",
		"tcp:443:", "tcp:443:0", "tcp:443:99999", "tcp:443:ephemeral", "icmp:1:2",
	} {
		if _, err := parseProbe(in); err == nil {
			t.Fatalf("parseProbe(%q): expected an error", in)
		}
	}
}

const testConfig = `
listen: ":9999"
defaults:
  interval: 30s
  timeout: 1s
  count: 3
targets:
  - name: edge
    host: 192.0.2.10
    labels: {provider: acme, region: eu-west-1}
    probes: [icmp, "tcp:443"]
  - name: site
    host: www.example.com
    labels: {provider: example}
    probes: [icmp]
    interval: 5s
  - host: 198.51.100.1
    probes: ["udp:53"]
    payload: "abcd"
`

func TestParseConfig(t *testing.T) {
	c, err := parseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}

	if c.Listen != ":9999" || !*c.Privileged {
		t.Fatalf("listen=%q privileged=%v", c.Listen, *c.Privileged)
	}
	// Durations must survive YAML decoding.
	if c.Defaults.Interval != 30*time.Second || c.Defaults.Timeout != time.Second {
		t.Fatalf("defaults not parsed: %+v", c.Defaults)
	}
	if c.Targets[1].Interval != 5*time.Second {
		t.Fatalf("per-target interval override lost: %v", c.Targets[1].Interval)
	}
	if c.Targets[0].Interval != 30*time.Second || c.Targets[0].Count != 3 {
		t.Fatalf("defaults not applied: %+v", c.Targets[0])
	}
	if c.Targets[2].Name != "198.51.100.1" {
		t.Fatalf("name should fall back to host, got %q", c.Targets[2].Name)
	}
	if !reflect.DeepEqual(c.Targets[2].payload, []byte{0xab, 0xcd}) {
		t.Fatalf("payload: %x", c.Targets[2].payload)
	}
	if !reflect.DeepEqual(c.Targets[0].parsed, []Probe{{Proto: "icmp"}, {Proto: "tcp", Port: 443}}) {
		t.Fatalf("probes: %+v", c.Targets[0].parsed)
	}
}

// The configurations shipped with the repository must stay loadable, otherwise
// the documented example is the first thing a new user finds broken.
func TestShippedConfigsParse(t *testing.T) {
	for _, path := range []string{"netprobe.yml", "examples/docker-compose/netprobe.yml"} {
		if _, err := LoadConfig(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

// The label key set must be identical across targets, otherwise registering the
// metrics panics at startup.
func TestLabelUnion(t *testing.T) {
	c, err := parseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"provider", "region"}; !reflect.DeepEqual(c.LabelKeys, want) {
		t.Fatalf("LabelKeys = %v, want %v", c.LabelKeys, want)
	}
	want := [][]string{
		{"acme", "eu-west-1"},
		{"example", ""}, // no region: empty value, not a missing key
		{"", ""},
	}
	for i, target := range c.Targets {
		if got := c.labelValues(target); !reflect.DeepEqual(got, want[i]) {
			t.Fatalf("labelValues(%s) = %v, want %v", target.Name, got, want[i])
		}
	}
}

func TestConfigRejectsBadInput(t *testing.T) {
	bad := map[string]string{
		"no targets":     "listen: \":1\"\n",
		"no host":        "targets:\n  - {probes: [icmp]}\n",
		"no probes":      "targets:\n  - {host: a}\n",
		"bad probe":      "targets:\n  - {host: a, probes: [gopher]}\n",
		"duplicate name": "targets:\n  - {host: a, probes: [icmp]}\n  - {host: a, probes: [icmp]}\n",
		"reserved label": "targets:\n  - {host: a, probes: [icmp], labels: {host: x}}\n",
		// Prometheus 3 accepts UTF-8 label names, so a name such as "a-b" is
		// valid. An empty name is invalid under every validation scheme.
		"empty label name": "targets:\n  - {host: a, probes: [icmp], labels: {\"\": x}}\n",
		"bad payload":      "targets:\n  - {host: a, probes: [\"udp:1\"], payload: \"zz\"}\n",
		"unknown field":    "targets:\n  - {host: a, probes: [icmp], colour: red}\n",
	}
	for name, cfg := range bad {
		if _, err := parseConfig([]byte(cfg)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// Label values must line up with the label names the metrics were declared
// with, otherwise WithLabelValues panics at runtime.
func TestMetricsAcceptEveryTarget(t *testing.T) {
	c, err := parseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	m := newMetrics(prometheus.NewRegistry(), c.LabelKeys)
	for _, target := range c.Targets {
		values := c.labelValues(target)
		for _, p := range target.parsed {
			lv := append([]string{target.Name, target.Host, p.Proto, p.PortLabel()}, values...)
			m.success.WithLabelValues(lv...).Set(1)
		}
	}
}

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
	p := newProber(mustProbe(t, "tcp:"+port), Target{}, false)

	r := p.Probe("127.0.0.1", 3, time.Second)
	if r.Received != 3 || r.Sent != 3 {
		t.Fatalf("open port: sent=%d received=%d err=%v", r.Sent, r.Received, r.Err)
	}
	if r.Avg <= 0 || r.Min > r.Avg || r.Avg > r.Max {
		t.Fatalf("inconsistent rtt statistics: %+v", r)
	}
	if r.IP != "127.0.0.1" {
		t.Fatalf("resolved ip = %q", r.IP)
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
	p := newProber(mustProbe(t, "tcp:"+port+":"+local), Target{}, false)

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
	p := newProber(mustProbe(t, "udp:"+port), Target{payload: []byte("ping")}, false)

	r := p.Probe("127.0.0.1", 3, time.Second)
	if r.Received != 3 {
		t.Fatalf("echo server: received=%d err=%v", r.Received, r.Err)
	}
	if r.Avg <= 0 {
		t.Fatalf("no rtt measured: %+v", r)
	}
}

// A closed UDP port must read as reachable through the ICMP port unreachable
// message the kernel reports as ECONNREFUSED. A single sample is used on
// purpose: Linux rate-limits ICMP unreachables to roughly one per second, so a
// multi-sample cycle would report phantom loss.
func TestUDPProbeClosedPortIsReachable(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()

	d, ip, err := udpRTT(addr, nil, []byte{0}, time.Second)
	if err != nil {
		t.Fatalf("closed port should be reachable, got %v", err)
	}
	if d <= 0 || ip != "127.0.0.1" {
		t.Fatalf("rtt=%v ip=%q", d, ip)
	}
}

func TestUDPProbeBlackholeIsLoss(t *testing.T) {
	// 203.0.113.0/24 is TEST-NET-3: routable in form, never answers.
	d, _, err := udpRTT("203.0.113.1:9", nil, []byte{0}, 300*time.Millisecond)
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

func mustProbe(t *testing.T, s string) Probe {
	t.Helper()
	p, err := parseProbe(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
