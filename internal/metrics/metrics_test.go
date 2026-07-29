package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Arylite/netprobe-exporter/internal/config"
)

// Label values must line up with the label names the metrics were declared
// with, otherwise WithLabelValues panics at runtime. Targets carrying
// different label keys, several address families and a traceroute all have to
// produce the same shape.
func TestSeriesAcceptEveryTarget(t *testing.T) {
	c, err := config.Parse([]byte(`
targets:
  - name: edge
    host: 192.0.2.10
    labels: {provider: acme, region: eu-west-1}
    probes: [icmp, "tcp:443"]
    traceroute: true
  - name: site
    host: www.example.com
    labels: {provider: example}
    probes: [icmp, "udp:53"]
    families: [ipv4, ipv6]
  - host: 198.51.100.1
    probes: ["udp:53"]
`))
	if err != nil {
		t.Fatal(err)
	}

	m := New(prometheus.NewRegistry(), c.LabelKeys)
	for _, target := range c.Targets {
		for _, f := range target.Families {
			for _, p := range target.Parsed {
				m.ProbeSeries(c.SeriesLabels(target, p, f))
			}
			m.PathSeries(c.PathSeriesLabels(target, f))
		}
	}
}
