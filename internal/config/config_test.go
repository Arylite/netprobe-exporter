package config

import (
	"reflect"
	"testing"
	"time"
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
		got, err := ParseProbe(in)
		if err != nil {
			t.Fatalf("ParseProbe(%q): unexpected error %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseProbe(%q) = %+v, want %+v", in, got, want)
		}
	}

	for _, in := range []string{
		"tcp", "tcp:", "tcp:0", "tcp:99999", "tcp:https", "icmp:1", "sctp:80", "",
		"tcp:443:", "tcp:443:0", "tcp:443:99999", "tcp:443:ephemeral", "icmp:1:2",
	} {
		if _, err := ParseProbe(in); err == nil {
			t.Fatalf("ParseProbe(%q): expected an error", in)
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

func TestParse(t *testing.T) {
	c, err := Parse([]byte(testConfig))
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
	if !reflect.DeepEqual(c.Targets[2].PayloadBytes, []byte{0xab, 0xcd}) {
		t.Fatalf("payload: %x", c.Targets[2].PayloadBytes)
	}
	if !reflect.DeepEqual(c.Targets[0].Parsed, []Probe{{Proto: "icmp"}, {Proto: "tcp", Port: 443}}) {
		t.Fatalf("probes: %+v", c.Targets[0].Parsed)
	}
}

// A target that does not pin an address family gets the resolver's choice,
// which is what a client connecting by name does.
func TestFamilyAndSubsystemDefaults(t *testing.T) {
	c, err := Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range c.Targets {
		if !reflect.DeepEqual(target.Families, []Family{FamilyAuto}) {
			t.Fatalf("%s: families = %v, want [auto]", target.Name, target.Families)
		}
	}
	if c.Traceroute.MaxHops != 20 || c.Traceroute.Interval != time.Minute {
		t.Fatalf("traceroute defaults: %+v", c.Traceroute)
	}
	// The access link watcher talks to a third party, so it stays off until a
	// server is named. Its timeout falls back to the probe timeout.
	if c.WAN.Server != "" || c.WAN.Timeout != c.Defaults.Timeout {
		t.Fatalf("wan defaults: %+v", c.WAN)
	}

	dual, err := Parse([]byte("targets:\n  - {host: a, probes: [icmp], families: [ipv4, ipv6], traceroute: true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := dual.Targets[0].Families; !reflect.DeepEqual(got, []Family{FamilyIPv4, FamilyIPv6}) {
		t.Fatalf("families = %v", got)
	}
	if !dual.Targets[0].Traceroute {
		t.Fatal("traceroute flag lost")
	}
}

// The configurations shipped with the repository must stay loadable, otherwise
// the documented example is the first thing a new user finds broken.
func TestShippedConfigsParse(t *testing.T) {
	for _, path := range []string{"../../netprobe.yml", "../../examples/docker-compose/netprobe.yml"} {
		if _, err := Load(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

// The label key set must be identical across targets, otherwise registering the
// metrics panics at startup.
func TestLabelUnion(t *testing.T) {
	c, err := Parse([]byte(testConfig))
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
		if got := c.LabelValues(target); !reflect.DeepEqual(got, want[i]) {
			t.Fatalf("LabelValues(%s) = %v, want %v", target.Name, got, want[i])
		}
	}
}

func TestRejectsBadInput(t *testing.T) {
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
		"unknown family":   "targets:\n  - {host: a, probes: [icmp], families: [ipv5]}\n",
		"duplicate family": "targets:\n  - {host: a, probes: [icmp], families: [ipv4, ipv4]}\n",
		// A literal address has one family; asking for the other one would
		// report a permanent outage that is really a typo.
		"family mismatch": "targets:\n  - {host: 192.0.2.1, probes: [icmp], families: [ipv6]}\n",
		"absurd max hops": "traceroute: {max_hops: 200}\ntargets:\n  - {host: a, probes: [icmp]}\n",
	}
	for name, cfg := range bad {
		if _, err := Parse([]byte(cfg)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
