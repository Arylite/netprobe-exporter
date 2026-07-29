// Package metrics declares every series the exporter publishes and binds the
// children each worker writes to.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Arylite/netprobe-exporter/internal/config"
)

// rttBuckets span half a millisecond to ten seconds. The range covers a local
// switch at one end and a saturated satellite link at the other; twenty
// buckets keep the series count reasonable while a native histogram, emitted
// alongside for the servers that support it, carries the fine detail.
var rttBuckets = prometheus.ExponentialBucketsRange(0.0005, 10, 20)

// Metrics holds every series the exporter publishes. They come in three label
// shapes: per probe, per target path, and one set for the access link itself.
type Metrics struct {
	// Per probe: one series for each target, protocol and address family.
	Success   *prometheus.GaugeVec
	RTT       *prometheus.GaugeVec
	RTTMin    *prometheus.GaugeVec
	RTTMax    *prometheus.GaugeVec
	RTTStdDev *prometheus.GaugeVec
	Jitter    *prometheus.GaugeVec
	Loss      *prometheus.GaugeVec
	MOS       *prometheus.GaugeVec
	RFactor   *prometheus.GaugeVec
	LastProbe *prometheus.GaugeVec
	DNSLookup *prometheus.GaugeVec
	Sent      *prometheus.CounterVec
	Received  *prometheus.CounterVec
	DNSErrors *prometheus.CounterVec
	SampleRTT *prometheus.HistogramVec
	Resolved  *prometheus.GaugeVec

	// Per target path, from the traceroute worker.
	PathHops     *prometheus.GaugeVec
	PathComplete *prometheus.GaugeVec
	PathHopRTT   *prometheus.GaugeVec
	PathHopInfo  *prometheus.GaugeVec
	PathChanges  *prometheus.CounterVec

	// The access link, from the STUN worker. One instance of each.
	WANSuccess prometheus.Gauge
	WANCGNAT   prometheus.Gauge
	WANChanges prometheus.Counter
	WANInfo    *prometheus.GaugeVec
}

func New(reg prometheus.Registerer, userLabels []string) *Metrics {
	probe := append(append([]string{}, config.FixedLabels...), userLabels...)
	path := append(append([]string{}, config.PathLabels...), userLabels...)
	hop := append(append([]string{}, path...), "hop")
	hopIP := append(append([]string{}, hop...), "ip")

	gauge := func(name, help string, labels []string) *prometheus.GaugeVec {
		v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
		reg.MustRegister(v)
		return v
	}
	counter := func(name, help string, labels []string) *prometheus.CounterVec {
		v := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
		reg.MustRegister(v)
		return v
	}
	plain := func(name, help string) prometheus.Gauge {
		v := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
		reg.MustRegister(v)
		return v
	}

	m := &Metrics{
		Success:   gauge("netprobe_probe_success", "1 if the last cycle received at least one reply.", probe),
		RTT:       gauge("netprobe_rtt_seconds", "Mean round-trip time of the last cycle.", probe),
		RTTMin:    gauge("netprobe_rtt_min_seconds", "Minimum round-trip time of the last cycle.", probe),
		RTTMax:    gauge("netprobe_rtt_max_seconds", "Maximum round-trip time of the last cycle.", probe),
		RTTStdDev: gauge("netprobe_rtt_stddev_seconds", "Round-trip time standard deviation of the last cycle.", probe),
		Jitter:    gauge("netprobe_jitter_seconds", "RFC 3550 interarrival jitter of the last cycle.", probe),
		Loss:      gauge("netprobe_loss_ratio", "Fraction of the last cycle's samples that received no reply.", probe),
		MOS:       gauge("netprobe_mos", "Estimated mean opinion score for voice, 1 to 4.5.", probe),
		RFactor:   gauge("netprobe_r_factor", "Estimated E-model transmission rating factor, 0 to 100.", probe),
		LastProbe: gauge("netprobe_last_probe_timestamp_seconds", "Unix timestamp of the last completed cycle.", probe),
		DNSLookup: gauge("netprobe_dns_lookup_seconds", "Time the last name resolution took. Absent for a literal address.", probe),
		Sent:      counter("netprobe_packets_sent_total", "Total samples sent.", probe),
		Received:  counter("netprobe_packets_received_total", "Total samples answered.", probe),
		DNSErrors: counter("netprobe_dns_failures_total", "Cycles that could not be probed because the name did not resolve.", probe),

		PathHops:     gauge("netprobe_path_hops", "Number of hops the last traceroute walked.", path),
		PathComplete: gauge("netprobe_path_complete", "1 if the last traceroute reached the target.", path),
		PathHopRTT:   gauge("netprobe_path_hop_rtt_seconds", "Round-trip time to each hop of the path.", hop),
		PathHopInfo:  gauge("netprobe_path_hop_info", "Address answering at each hop of the path.", hopIP),
		PathChanges:  counter("netprobe_path_changes_total", "Times the sequence of hops changed.", path),

		WANSuccess: plain("netprobe_wan_probe_success", "1 if the last STUN query answered."),
		WANCGNAT:   plain("netprobe_wan_behind_cgnat", "1 if the local address sits in the RFC 6598 carrier grade NAT range."),
		WANChanges: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netprobe_wan_ip_changes_total",
			Help: "Times the public address changed, which is how a client sees its access link reconnect.",
		}),
	}

	// The per-sample distribution, which the gauges above cannot give: they
	// only ever hold the last cycle, so no quantile can be computed over a
	// window. Both bucket schemes are emitted, the classic one for any
	// Prometheus and the native one where it is enabled.
	m.SampleRTT = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:                            "netprobe_sample_rtt_seconds",
		Help:                            "Round-trip time of every individual sample.",
		Buckets:                         rttBuckets,
		NativeHistogramBucketFactor:     1.1,
		NativeHistogramMaxBucketNumber:  160,
		NativeHistogramMinResetDuration: time.Hour,
	}, probe)

	m.Resolved = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "netprobe_resolved_ip_info", Help: "Address the target currently resolves to."},
		[]string{"name", "host", "proto", "family", "ip"},
	)
	m.WANInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "netprobe_wan_ip_info", Help: "Public address of this host, and the local address it goes out from."},
		[]string{"ip", "local_ip"},
	)
	reg.MustRegister(m.SampleRTT, m.Resolved, m.WANInfo, m.WANChanges)
	return m
}

// ProbeSeries is the set of children belonging to one probe. Binding them once
// at startup turns a label mismatch into an immediate panic rather than a
// failure on the first cycle, and saves a map lookup per metric per cycle.
type ProbeSeries struct {
	Success   prometheus.Gauge
	RTT       prometheus.Gauge
	RTTMin    prometheus.Gauge
	RTTMax    prometheus.Gauge
	RTTStdDev prometheus.Gauge
	Jitter    prometheus.Gauge
	Loss      prometheus.Gauge
	MOS       prometheus.Gauge
	RFactor   prometheus.Gauge
	LastProbe prometheus.Gauge
	DNSLookup prometheus.Gauge
	Sent      prometheus.Counter
	Received  prometheus.Counter
	DNSErrors prometheus.Counter
	SampleRTT prometheus.Observer
}

func (m *Metrics) ProbeSeries(lv []string) *ProbeSeries {
	return &ProbeSeries{
		Success:   m.Success.WithLabelValues(lv...),
		RTT:       m.RTT.WithLabelValues(lv...),
		RTTMin:    m.RTTMin.WithLabelValues(lv...),
		RTTMax:    m.RTTMax.WithLabelValues(lv...),
		RTTStdDev: m.RTTStdDev.WithLabelValues(lv...),
		Jitter:    m.Jitter.WithLabelValues(lv...),
		Loss:      m.Loss.WithLabelValues(lv...),
		MOS:       m.MOS.WithLabelValues(lv...),
		RFactor:   m.RFactor.WithLabelValues(lv...),
		LastProbe: m.LastProbe.WithLabelValues(lv...),
		DNSLookup: m.DNSLookup.WithLabelValues(lv...),
		Sent:      m.Sent.WithLabelValues(lv...),
		Received:  m.Received.WithLabelValues(lv...),
		DNSErrors: m.DNSErrors.WithLabelValues(lv...),
		SampleRTT: m.SampleRTT.WithLabelValues(lv...),
	}
}

// PathSeries is the target-level part of a traceroute. The per-hop metrics are
// not bound here: their hop label is only known once the trace has run.
type PathSeries struct {
	Hops     prometheus.Gauge
	Complete prometheus.Gauge
	Changes  prometheus.Counter
}

func (m *Metrics) PathSeries(lv []string) *PathSeries {
	return &PathSeries{
		Hops:     m.PathHops.WithLabelValues(lv...),
		Complete: m.PathComplete.WithLabelValues(lv...),
		Changes:  m.PathChanges.WithLabelValues(lv...),
	}
}
