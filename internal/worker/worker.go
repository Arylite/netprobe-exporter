// Package worker runs the measurement loops: one per probe, one per traced
// path, and one for the access link.
package worker

import (
	"log"
	"math"
	"net/netip"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Arylite/netprobe-exporter/internal/config"
	"github.com/Arylite/netprobe-exporter/internal/metrics"
	"github.com/Arylite/netprobe-exporter/internal/probe"
)

// Start launches one worker per target, protocol and address family, plus the
// traceroute and access link watchers, and reports how many of each it ran.
// Every series is bound here so that a label mismatch panics at startup rather
// than on the first cycle of a probe nobody is watching.
func Start(m *metrics.Metrics, cfg *config.Config) (probes, paths int) {
	tracer := probe.Tracer{
		Privileged: *cfg.Privileged,
		MaxHops:    cfg.Traceroute.MaxHops,
		Timeout:    cfg.Traceroute.Timeout,
	}

	for _, t := range cfg.Targets {
		for _, f := range t.Families {
			for _, p := range t.Parsed {
				w := &probeWorker{
					m:      m,
					series: m.ProbeSeries(cfg.SeriesLabels(t, p, f)),
					target: t,
					probe:  p,
					family: f,
					prober: probe.New(p, t, *cfg.Privileged),
				}
				go w.run()
				probes++
			}

			if !t.Traceroute {
				continue
			}
			labels := cfg.PathSeriesLabels(t, f)
			w := &pathWorker{
				m:        m,
				series:   m.PathSeries(labels),
				labels:   labels,
				target:   t,
				family:   f,
				tracer:   tracer,
				interval: cfg.Traceroute.Interval,
			}
			go w.run()
			paths++
		}
	}

	if cfg.WAN.Server != "" {
		go (&wanWorker{m: m, cfg: cfg.WAN}).run()
	}
	return probes, paths
}

// probeWorker measures one target, over one protocol, over one address family,
// until the process exits.
type probeWorker struct {
	m      *metrics.Metrics
	series *metrics.ProbeSeries
	target config.Target
	probe  config.Probe
	family config.Family
	prober probe.Prober

	lastIP netip.Addr // to keep the info series stable while the address holds
}

func (w *probeWorker) run() {
	tick := time.NewTicker(w.target.Interval)
	defer tick.Stop()
	for {
		w.cycle()
		<-tick.C
	}
}

func (w *probeWorker) cycle() {
	s := w.series
	s.LastProbe.SetToCurrentTime()

	res := probe.Resolve(w.target.Host, w.family, w.target.Timeout)
	if res.Looked {
		s.DNSLookup.Set(res.Latency.Seconds())
	}
	if res.Err != nil {
		// The packet counters stay untouched: nothing was sent, so this is a
		// failure of the name, not loss on the wire. netprobe_probe_success
		// and netprobe_dns_failures_total are what report it.
		s.DNSErrors.Inc()
		s.Loss.Set(1)
		w.gap()
		log.Printf("%s %s: %v", w.target.Name, w.probe, res.Err)
		return
	}
	w.setResolved(res.IP)

	r := w.prober.Probe(res.IP.String(), w.target.Count, w.target.Timeout)
	s.Sent.Add(float64(r.Sent))
	s.Received.Add(float64(r.Received))

	var loss float64
	if r.Sent > 0 {
		// A duplicate reply can push received past sent, which would otherwise
		// surface as a negative loss ratio.
		loss = math.Min(1, math.Max(0, 1-float64(r.Received)/float64(r.Sent)))
		s.Loss.Set(loss)
	}

	if r.Received == 0 {
		w.gap()
		if r.Err != nil {
			log.Printf("%s %s: %v", w.target.Name, w.probe, r.Err)
		}
		return
	}

	for _, d := range r.RTTs {
		s.SampleRTT.Observe(d.Seconds())
	}
	jitter := probe.Jitter(r.RTTs)
	q := probe.VoiceQuality(r.Avg, jitter, loss)

	s.Success.Set(1)
	s.RTT.Set(r.Avg.Seconds())
	s.RTTMin.Set(r.Min.Seconds())
	s.RTTMax.Set(r.Max.Seconds())
	s.RTTStdDev.Set(r.StdDev.Seconds())
	s.Jitter.Set(jitter.Seconds())
	s.MOS.Set(q.MOS)
	s.RFactor.Set(q.R)
}

// gap marks the cycle as failed and sets every measurement to NaN, so that a
// consumer renders a hole rather than a flat line held at the last good value.
func (w *probeWorker) gap() {
	s := w.series
	s.Success.Set(0)
	for _, g := range []prometheus.Gauge{s.RTT, s.RTTMin, s.RTTMax, s.RTTStdDev, s.Jitter, s.MOS, s.RFactor} {
		g.Set(math.NaN())
	}
}

// setResolved republishes the address series only when the address actually
// changed. Deleting and recreating it every cycle would leave a window in
// which a scrape sees no series at all.
func (w *probeWorker) setResolved(ip netip.Addr) {
	if ip == w.lastIP {
		return
	}
	w.m.Resolved.DeletePartialMatch(prometheus.Labels{
		"name": w.target.Name, "proto": w.probe.Proto, "family": string(w.family),
	})
	w.m.Resolved.WithLabelValues(
		w.target.Name, w.target.Host, w.probe.Proto, string(w.family), ip.String(),
	).Set(1)
	w.lastIP = ip
}

// pathWorker walks the route to one target. It runs on its own slow interval
// because a trace costs up to max_hops timeouts and the answer it gives, where
// on the path the latency or the loss appears, changes on the scale of minutes.
type pathWorker struct {
	m        *metrics.Metrics
	series   *metrics.PathSeries
	labels   []string // PathSeriesLabels of this target
	target   config.Target
	family   config.Family
	tracer   probe.Tracer
	interval time.Duration

	last string // fingerprint of the previous trace
}

func (w *pathWorker) run() {
	tick := time.NewTicker(w.interval)
	defer tick.Stop()
	for {
		w.cycle()
		<-tick.C
	}
}

func (w *pathWorker) cycle() {
	res := probe.Resolve(w.target.Host, w.family, w.target.Timeout)
	if res.Err != nil {
		w.series.Complete.Set(0)
		return
	}

	path, err := w.tracer.Trace(res.IP)
	if err != nil {
		w.series.Complete.Set(0)
		log.Printf("%s traceroute: %v", w.target.Name, err)
		return
	}

	// The hop series are rebuilt only when the route changes, which also
	// clears the tail left behind by a route that got shorter.
	if fp := path.Fingerprint(); fp != w.last {
		if w.last != "" {
			w.series.Changes.Inc()
			log.Printf("%s traceroute: path changed to %s", w.target.Name, fp)
		}
		w.resetHops()
		for i, hop := range path.Hops {
			if hop.IP.IsValid() {
				w.m.PathHopInfo.WithLabelValues(append(w.hopLabels(i), hop.IP.String())...).Set(1)
			}
		}
		w.last = fp
	}

	w.series.Hops.Set(float64(len(path.Hops)))
	w.series.Complete.Set(boolValue(path.Complete))
	for i, hop := range path.Hops {
		rtt := math.NaN() // a hop that stays silent is normal, not a hole in the path
		if hop.IP.IsValid() {
			rtt = hop.RTT.Seconds()
		}
		w.m.PathHopRTT.WithLabelValues(w.hopLabels(i)...).Set(rtt)
	}
}

// hopLabels are the path labels of this target plus the one based hop index.
func (w *pathWorker) hopLabels(i int) []string {
	return append(append([]string{}, w.labels...), strconv.Itoa(i+1))
}

func (w *pathWorker) resetHops() {
	sel := prometheus.Labels{"name": w.target.Name, "family": string(w.family)}
	w.m.PathHopRTT.DeletePartialMatch(sel)
	w.m.PathHopInfo.DeletePartialMatch(sel)
}

// wanWorker watches the address the outside world sees for this host. A change
// means the access link renegotiated, which nothing else on the client side
// records; the exporter is often the only witness that the line dropped at 4am.
type wanWorker struct {
	m   *metrics.Metrics
	cfg config.WAN

	last probe.WANAddress
}

func (w *wanWorker) run() {
	tick := time.NewTicker(w.cfg.Interval)
	defer tick.Stop()
	for {
		w.cycle()
		<-tick.C
	}
}

func (w *wanWorker) cycle() {
	addr, err := probe.QueryWAN(w.cfg.Server, w.cfg.Timeout)
	if err != nil {
		w.m.WANSuccess.Set(0)
		log.Printf("wan %s: %v", w.cfg.Server, err)
		return
	}
	w.m.WANSuccess.Set(1)
	w.m.WANCGNAT.Set(boolValue(addr.BehindCGNAT()))

	if addr == w.last {
		return
	}
	if w.last.Public.IsValid() && addr.Public != w.last.Public {
		w.m.WANChanges.Inc()
		log.Printf("wan: public address changed from %s to %s", w.last.Public, addr.Public)
	}
	w.m.WANInfo.Reset() // exactly one address is current
	w.m.WANInfo.WithLabelValues(addr.Public.String(), addr.Local.String()).Set(1)
	w.last = addr
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
