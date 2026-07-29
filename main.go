// Command netprobe-exporter continuously probes a set of hosts over ICMP, TCP
// and UDP and exposes round-trip time, packet loss and jitter to Prometheus.
package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Set at build time with -ldflags "-X main.version=...".
var (
	version   = "dev"
	revision  = "unknown"
	buildDate = "unknown"
)

type metrics struct {
	success   *prometheus.GaugeVec
	rtt       *prometheus.GaugeVec
	rttMin    *prometheus.GaugeVec
	rttMax    *prometheus.GaugeVec
	rttStdDev *prometheus.GaugeVec
	loss      *prometheus.GaugeVec
	lastProbe *prometheus.GaugeVec
	sent      *prometheus.CounterVec
	received  *prometheus.CounterVec
	resolved  *prometheus.GaugeVec
}

func newMetrics(reg prometheus.Registerer, userLabels []string) *metrics {
	labels := append(append([]string{}, fixedLabels...), userLabels...)
	gauge := func(name, help string) *prometheus.GaugeVec {
		v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
		reg.MustRegister(v)
		return v
	}
	counter := func(name, help string) *prometheus.CounterVec {
		v := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
		reg.MustRegister(v)
		return v
	}

	m := &metrics{
		success:   gauge("netprobe_probe_success", "1 if the last cycle received at least one reply."),
		rtt:       gauge("netprobe_rtt_seconds", "Mean round-trip time of the last cycle."),
		rttMin:    gauge("netprobe_rtt_min_seconds", "Minimum round-trip time of the last cycle."),
		rttMax:    gauge("netprobe_rtt_max_seconds", "Maximum round-trip time of the last cycle."),
		rttStdDev: gauge("netprobe_rtt_stddev_seconds", "Round-trip time standard deviation of the last cycle."),
		loss:      gauge("netprobe_loss_ratio", "Fraction of the last cycle's samples that received no reply."),
		lastProbe: gauge("netprobe_last_probe_timestamp_seconds", "Unix timestamp of the last completed cycle."),
		sent:      counter("netprobe_packets_sent_total", "Total samples sent."),
		received:  counter("netprobe_packets_received_total", "Total samples answered."),
	}
	m.resolved = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "netprobe_resolved_ip_info", Help: "Address the target currently resolves to."},
		[]string{"name", "host", "proto", "ip"},
	)
	reg.MustRegister(m.resolved)
	return m
}

// worker probes a single target/probe pair until the process exits.
func worker(m *metrics, t Target, p Probe, pr Prober, userValues []string) {
	lv := append([]string{t.Name, t.Host, p.Proto, p.PortLabel()}, userValues...)
	// Bind the children once so a label mismatch fails at startup, not mid-run.
	var (
		success   = m.success.WithLabelValues(lv...)
		rtt       = m.rtt.WithLabelValues(lv...)
		rttMin    = m.rttMin.WithLabelValues(lv...)
		rttMax    = m.rttMax.WithLabelValues(lv...)
		rttStdDev = m.rttStdDev.WithLabelValues(lv...)
		loss      = m.loss.WithLabelValues(lv...)
		lastProbe = m.lastProbe.WithLabelValues(lv...)
		sent      = m.sent.WithLabelValues(lv...)
		received  = m.received.WithLabelValues(lv...)
	)

	tick := time.NewTicker(t.Interval)
	defer tick.Stop()
	for {
		r := pr.Probe(t.Host, t.Count, t.Timeout)

		sent.Add(float64(r.Sent))
		received.Add(float64(r.Received))
		lastProbe.SetToCurrentTime()
		if r.Sent > 0 {
			loss.Set(1 - float64(r.Received)/float64(r.Sent))
		}
		if r.Received > 0 {
			success.Set(1)
			rtt.Set(r.Avg.Seconds())
			rttMin.Set(r.Min.Seconds())
			rttMax.Set(r.Max.Seconds())
			rttStdDev.Set(r.StdDev.Seconds())
		} else {
			success.Set(0)
			// Report NaN rather than a stale value so consumers render a gap.
			for _, g := range []prometheus.Gauge{rtt, rttMin, rttMax, rttStdDev} {
				g.Set(math.NaN())
			}
			if r.Err != nil {
				log.Printf("%s %s: %v", t.Name, p, r.Err)
			}
		}
		if r.IP != "" {
			// Drop the previous address so a re-resolved target does not leave a
			// stale series pinned at 1.
			m.resolved.DeletePartialMatch(prometheus.Labels{"name": t.Name, "proto": p.Proto})
			m.resolved.WithLabelValues(t.Name, t.Host, p.Proto, r.IP).Set(1)
		}

		<-tick.C
	}
}

func main() {
	cfgPath := flag.String("config", "/etc/netprobe/netprobe.yml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("netprobe-exporter %s (revision %s, built %s, %s)\n",
			version, revision, buildDate, runtime.Version())
		return
	}

	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	buildInfo := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "netprobe_build_info", Help: "Build information about netprobe-exporter."},
		[]string{"version", "revision", "goversion"},
	)
	buildInfo.WithLabelValues(version, revision, runtime.Version()).Set(1)
	reg.MustRegister(buildInfo)

	m := newMetrics(reg, cfg.LabelKeys)

	probes := 0
	for _, t := range cfg.Targets {
		values := cfg.labelValues(t)
		for _, p := range t.parsed {
			go worker(m, t, p, newProber(p, t, *cfg.Privileged), values)
			probes++
		}
	}
	log.Printf("netprobe-exporter %s: %d targets, %d probes, labels %v, listening on %s",
		version, len(cfg.Targets), probes, cfg.LabelKeys, cfg.Listen)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/-/healthy", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/metrics", http.StatusFound)
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
