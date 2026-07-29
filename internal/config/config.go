// Package config loads and validates the exporter's configuration, and owns
// the label sets every metric is built from.
package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/model"
	"gopkg.in/yaml.v3"
)

// FixedLabels are attached to every probe metric, ahead of the user labels.
// A user label reusing one of these names would produce a duplicate, so
// configuration validation rejects it.
var FixedLabels = []string{"name", "host", "proto", "port", "family"}

// PathLabels identify a traceroute, which belongs to a target rather than to
// one of its probes and so carries no protocol and no port.
var PathLabels = []string{"name", "host", "family"}

type Defaults struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	Count    int           `yaml:"count"`
}

// Traceroute configures the path probing shared by every target that asks for
// it. It runs on its own slow interval: a trace costs up to max_hops timeouts
// and answers a question that changes on the scale of minutes, not seconds.
type Traceroute struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	MaxHops  int           `yaml:"max_hops"`
}

// WAN configures the STUN lookup of the public address. It is disabled unless
// a server is named: the exporter should not talk to a third party that the
// operator did not choose.
type WAN struct {
	Server   string        `yaml:"server"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
}

type Target struct {
	Name       string            `yaml:"name"`
	Host       string            `yaml:"host"`
	Labels     map[string]string `yaml:"labels"`
	Probes     []string          `yaml:"probes"`
	Families   []Family          `yaml:"families"`
	Traceroute bool              `yaml:"traceroute"`
	Payload    string            `yaml:"payload"` // hex, udp only
	Interval   time.Duration     `yaml:"interval"`
	Timeout    time.Duration     `yaml:"timeout"`
	Count      int               `yaml:"count"`

	Parsed       []Probe `yaml:"-"` // filled by Parse
	PayloadBytes []byte  `yaml:"-"`
}

type Config struct {
	Listen     string     `yaml:"listen"`
	Privileged *bool      `yaml:"privileged"`
	Defaults   Defaults   `yaml:"defaults"`
	Traceroute Traceroute `yaml:"traceroute"`
	WAN        WAN        `yaml:"wan"`
	Targets    []Target   `yaml:"targets"`

	LabelKeys []string `yaml:"-"` // union of every target's label keys, sorted
}

type Probe struct {
	Proto     string // icmp, tcp, udp
	Port      int    // destination port, 0 for icmp
	LocalPort int    // source port to bind to, 0 for an ephemeral one
}

// PortLabel is the "port" label value: empty for protocols without a port.
func (p Probe) PortLabel() string {
	if p.Port == 0 {
		return ""
	}
	return strconv.Itoa(p.Port)
}

func (p Probe) String() string {
	if p.Port == 0 {
		return p.Proto
	}
	s := p.Proto + ":" + strconv.Itoa(p.Port)
	if p.LocalPort != 0 {
		s += ":" + strconv.Itoa(p.LocalPort)
	}
	return s
}

// ParseProbe turns "icmp", "tcp:443" or "udp:53:5353" into a Probe. The
// optional third field pins the local source port, which is ephemeral by
// default; ICMP has no ports at all.
func ParseProbe(s string) (Probe, error) {
	proto, rest, hasPort := strings.Cut(strings.TrimSpace(s), ":")
	proto = strings.ToLower(proto)
	portStr, localStr, hasLocal := strings.Cut(rest, ":")
	switch proto {
	case "icmp":
		if hasPort {
			return Probe{}, fmt.Errorf("probe %q: icmp takes no port", s)
		}
		return Probe{Proto: proto}, nil
	case "tcp", "udp":
		if !hasPort {
			return Probe{}, fmt.Errorf("probe %q: %s needs a port (e.g. %s:443)", s, proto, proto)
		}
		port, err := parsePort(portStr)
		if err != nil {
			return Probe{}, fmt.Errorf("probe %q: %w", s, err)
		}
		local := 0
		if hasLocal {
			if local, err = parsePort(localStr); err != nil {
				return Probe{}, fmt.Errorf("probe %q: local %w", s, err)
			}
		}
		return Probe{Proto: proto, Port: port, LocalPort: local}, nil
	default:
		return Probe{}, fmt.Errorf("probe %q: unknown protocol %q (want icmp, tcp or udp)", s, proto)
	}
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return n, nil
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) (*Config, error) {
	c := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true) // reject unknown keys instead of silently ignoring them
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	if c.Listen == "" {
		c.Listen = ":9427"
	}
	if c.Privileged == nil {
		yes := true
		c.Privileged = &yes
	}
	if c.Defaults.Interval <= 0 {
		c.Defaults.Interval = 15 * time.Second
	}
	if c.Defaults.Timeout <= 0 {
		c.Defaults.Timeout = 2 * time.Second
	}
	if c.Defaults.Count <= 0 {
		c.Defaults.Count = 5
	}
	if c.Traceroute.Interval <= 0 {
		c.Traceroute.Interval = time.Minute
	}
	if c.Traceroute.Timeout <= 0 {
		c.Traceroute.Timeout = time.Second
	}
	if c.Traceroute.MaxHops <= 0 {
		c.Traceroute.MaxHops = 20
	}
	if c.Traceroute.MaxHops > 64 {
		return nil, fmt.Errorf("config: traceroute max_hops %d is above 64", c.Traceroute.MaxHops)
	}
	if c.WAN.Interval <= 0 {
		c.WAN.Interval = time.Minute
	}
	if c.WAN.Timeout <= 0 {
		c.WAN.Timeout = c.Defaults.Timeout
	}
	if len(c.Targets) == 0 {
		return nil, errors.New("config: no targets")
	}

	seen := make(map[string]bool, len(c.Targets))
	for i := range c.Targets {
		t := &c.Targets[i]
		if t.Host == "" {
			return nil, fmt.Errorf("config: target %d: host is required", i)
		}
		if t.Name == "" {
			t.Name = t.Host
		}
		if seen[t.Name] {
			return nil, fmt.Errorf("config: duplicate target name %q", t.Name)
		}
		seen[t.Name] = true

		if t.Interval <= 0 {
			t.Interval = c.Defaults.Interval
		}
		if t.Timeout <= 0 {
			t.Timeout = c.Defaults.Timeout
		}
		if t.Count <= 0 {
			t.Count = c.Defaults.Count
		}

		if len(t.Probes) == 0 {
			return nil, fmt.Errorf("config: target %q: no probes", t.Name)
		}
		for _, s := range t.Probes {
			p, err := ParseProbe(s)
			if err != nil {
				return nil, fmt.Errorf("config: target %q: %w", t.Name, err)
			}
			t.Parsed = append(t.Parsed, p)
		}

		families := map[Family]bool{}
		for _, f := range t.Families {
			if f != FamilyIPv4 && f != FamilyIPv6 {
				return nil, fmt.Errorf("config: target %q: unknown family %q (want ipv4 or ipv6)", t.Name, f)
			}
			if families[f] {
				return nil, fmt.Errorf("config: target %q: family %q listed twice", t.Name, f)
			}
			families[f] = true
			// A literal address belongs to one family; probing it over the
			// other reports a permanent outage that is really a typo.
			if addr, err := netip.ParseAddr(t.Host); err == nil && !f.Matches(addr) {
				return nil, fmt.Errorf("config: target %q: host %s is not %s", t.Name, t.Host, f)
			}
		}
		if len(t.Families) == 0 {
			// Left to the resolver, exactly as a client that connects by name.
			t.Families = []Family{FamilyAuto}
		}

		if t.Payload != "" {
			raw, err := hex.DecodeString(strings.TrimSpace(t.Payload))
			if err != nil {
				return nil, fmt.Errorf("config: target %q: payload is not valid hex: %w", t.Name, err)
			}
			t.PayloadBytes = raw
		}
		if len(t.PayloadBytes) == 0 {
			t.PayloadBytes = []byte{0} // a datagram must carry at least one byte
		}

		for k := range t.Labels {
			if !model.LabelName(k).IsValid() {
				return nil, fmt.Errorf("config: target %q: %q is not a valid Prometheus label name", t.Name, k)
			}
			for _, r := range FixedLabels {
				if k == r {
					return nil, fmt.Errorf("config: target %q: label %q is reserved by the exporter", t.Name, k)
				}
			}
		}
	}

	c.LabelKeys = labelUnion(c.Targets)
	return c, nil
}

// labelUnion returns the sorted set of every label key used by any target.
// Prometheus requires an identical label key set across all series of a metric,
// so a target missing a key is given an empty value rather than no key at all.
func labelUnion(targets []Target) []string {
	set := map[string]bool{}
	for _, t := range targets {
		for k := range t.Labels {
			set[k] = true
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// LabelValues returns t's label values aligned with c.LabelKeys.
func (c *Config) LabelValues(t Target) []string {
	vals := make([]string, len(c.LabelKeys))
	for i, k := range c.LabelKeys {
		vals[i] = t.Labels[k]
	}
	return vals
}

// SeriesLabels are the label values of one probe series, in the order the
// metrics declare them: FixedLabels first, then the user labels.
func (c *Config) SeriesLabels(t Target, p Probe, f Family) []string {
	return append([]string{t.Name, t.Host, p.Proto, p.PortLabel(), string(f)}, c.LabelValues(t)...)
}

// PathSeriesLabels are the label values of one traceroute series, matching
// PathLabels followed by the user labels.
func (c *Config) PathSeriesLabels(t Target, f Family) []string {
	return append([]string{t.Name, t.Host, string(f)}, c.LabelValues(t)...)
}
