package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/model"
	"gopkg.in/yaml.v3"
)

// fixedLabels are attached to every probe metric, ahead of the user labels.
// A user label reusing one of these names would produce a duplicate, so
// configuration validation rejects it.
var fixedLabels = []string{"name", "host", "proto", "port"}

type Defaults struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	Count    int           `yaml:"count"`
}

type Target struct {
	Name     string            `yaml:"name"`
	Host     string            `yaml:"host"`
	Labels   map[string]string `yaml:"labels"`
	Probes   []string          `yaml:"probes"`
	Payload  string            `yaml:"payload"` // hex, udp only
	Interval time.Duration     `yaml:"interval"`
	Timeout  time.Duration     `yaml:"timeout"`
	Count    int               `yaml:"count"`

	parsed  []Probe // filled by parseConfig
	payload []byte
}

type Config struct {
	Listen     string   `yaml:"listen"`
	Privileged *bool    `yaml:"privileged"`
	Defaults   Defaults `yaml:"defaults"`
	Targets    []Target `yaml:"targets"`

	LabelKeys []string `yaml:"-"` // union of every target's label keys, sorted
}

type Probe struct {
	Proto string // icmp, tcp, udp
	Port  int    // 0 for icmp
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
	return p.Proto + ":" + strconv.Itoa(p.Port)
}

// parseProbe turns "icmp", "tcp:443" or "udp:53" into a Probe.
func parseProbe(s string) (Probe, error) {
	proto, portStr, hasPort := strings.Cut(strings.TrimSpace(s), ":")
	proto = strings.ToLower(proto)
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
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return Probe{}, fmt.Errorf("probe %q: bad port %q", s, portStr)
		}
		return Probe{Proto: proto, Port: port}, nil
	default:
		return Probe{}, fmt.Errorf("probe %q: unknown protocol %q (want icmp, tcp or udp)", s, proto)
	}
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(b)
}

func parseConfig(b []byte) (*Config, error) {
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
			p, err := parseProbe(s)
			if err != nil {
				return nil, fmt.Errorf("config: target %q: %w", t.Name, err)
			}
			t.parsed = append(t.parsed, p)
		}

		if t.Payload != "" {
			raw, err := hex.DecodeString(strings.TrimSpace(t.Payload))
			if err != nil {
				return nil, fmt.Errorf("config: target %q: payload is not valid hex: %w", t.Name, err)
			}
			t.payload = raw
		}
		if len(t.payload) == 0 {
			t.payload = []byte{0} // a datagram must carry at least one byte
		}

		for k := range t.Labels {
			if !model.LabelName(k).IsValid() {
				return nil, fmt.Errorf("config: target %q: %q is not a valid Prometheus label name", t.Name, k)
			}
			for _, r := range fixedLabels {
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

// labelValues returns t's label values aligned with c.LabelKeys.
func (c *Config) labelValues(t Target) []string {
	vals := make([]string, len(c.LabelKeys))
	for i, k := range c.LabelKeys {
		vals[i] = t.Labels[k]
	}
	return vals
}
