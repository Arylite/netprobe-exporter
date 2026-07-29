// Command netprobe-exporter continuously probes a set of hosts over ICMP, TCP
// and UDP and exposes round-trip time, packet loss, jitter, voice quality, the
// path taken and the state of the access link to Prometheus.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Arylite/netprobe-exporter/internal/config"
	"github.com/Arylite/netprobe-exporter/internal/metrics"
	"github.com/Arylite/netprobe-exporter/internal/worker"
)

// Set at build time with -ldflags "-X main.version=...".
var (
	version   = "dev"
	revision  = "unknown"
	buildDate = "unknown"
)

func main() {
	cfgPath := flag.String("config", "/etc/netprobe/netprobe.yml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("netprobe-exporter %s (revision %s, built %s, %s)\n",
			version, revision, buildDate, runtime.Version())
		return
	}

	cfg, err := config.Load(*cfgPath)
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

	m := metrics.New(reg, cfg.LabelKeys)
	probes, paths := worker.Start(m, cfg)

	log.Printf("netprobe-exporter %s: %d targets, %d probes, %d traceroutes, labels %v, listening on %s",
		version, len(cfg.Targets), probes, paths, cfg.LabelKeys, cfg.Listen)
	if cfg.WAN.Server != "" {
		log.Printf("watching the access link through %s every %s", cfg.WAN.Server, cfg.WAN.Interval)
	}

	if err := serve(cfg.Listen, reg); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func serve(listen string, reg *prometheus.Registry) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		// Native histograms only travel over the protobuf exposition format.
		EnableOpenMetrics: true,
	}))
	mux.HandleFunc("/-/healthy", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/metrics", http.StatusFound)
	})

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return srv.ListenAndServe()
}
