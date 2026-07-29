package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

const dashboardDir = "examples/docker-compose/grafana/dashboards"

// datasourceUID must match the uid in provisioning/datasources/prometheus.yml.
const datasourceUID = "prometheus"

// exportedMetricNames returns every metric name the exporter can publish, taken
// from the registry rather than a hand-written list, so renaming a metric fails
// this test instead of silently breaking the provisioned dashboards.
func exportedMetricNames(t *testing.T) map[string]bool {
	t.Helper()

	reg := prometheus.NewRegistry()
	m := newMetrics(reg, nil)

	// A vec with no children collects nothing, so bind one of each.
	lv := []string{"target", "host", "icmp", ""}
	m.success.WithLabelValues(lv...)
	m.rtt.WithLabelValues(lv...)
	m.rttMin.WithLabelValues(lv...)
	m.rttMax.WithLabelValues(lv...)
	m.rttStdDev.WithLabelValues(lv...)
	m.loss.WithLabelValues(lv...)
	m.lastProbe.WithLabelValues(lv...)
	m.sent.WithLabelValues(lv...)
	m.received.WithLabelValues(lv...)
	m.resolved.WithLabelValues("target", "host", "icmp", "192.0.2.1")

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := map[string]bool{
		// Registered in main() rather than newMetrics.
		"netprobe_build_info": true,
	}
	for _, f := range families {
		names[f.GetName()] = true
	}
	return names
}

type dashboard struct {
	UID    string `json:"uid"`
	Title  string `json:"title"`
	Panels []struct {
		ID         int    `json:"id"`
		Type       string `json:"type"`
		Title      string `json:"title"`
		Datasource *struct {
			UID string `json:"uid"`
		} `json:"datasource"`
		Targets []struct {
			Expr string `json:"expr"`
		} `json:"targets"`
	} `json:"panels"`
}

var metricRef = regexp.MustCompile(`netprobe_[a-z_]+`)

func TestDashboards(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(dashboardDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no dashboards found in %s: %v", dashboardDir, err)
	}

	known := exportedMetricNames(t)
	uids := map[string]string{}

	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		var d dashboard
		if err := json.Unmarshal(raw, &d); err != nil {
			// Grafana silently refuses to provision a dashboard that does not
			// parse, so an invalid file looks like a missing one at runtime.
			t.Errorf("%s: invalid JSON: %v", file, err)
			continue
		}

		if d.UID == "" || d.Title == "" {
			t.Errorf("%s: uid and title are required", file)
		}
		if other, dup := uids[d.UID]; dup {
			t.Errorf("%s: uid %q already used by %s", file, d.UID, other)
		}
		uids[d.UID] = file

		ids := map[int]bool{}
		for _, p := range d.Panels {
			if ids[p.ID] {
				t.Errorf("%s: duplicate panel id %d (%q)", file, p.ID, p.Title)
			}
			ids[p.ID] = true

			if p.Type == "row" {
				continue
			}
			if p.Datasource == nil || p.Datasource.UID != datasourceUID {
				t.Errorf("%s: panel %q does not point at the %q datasource", file, p.Title, datasourceUID)
			}
			if len(p.Targets) == 0 {
				t.Errorf("%s: panel %q has no queries", file, p.Title)
			}
			for _, target := range p.Targets {
				for _, name := range metricRef.FindAllString(target.Expr, -1) {
					if !known[name] {
						t.Errorf("%s: panel %q queries unknown metric %q", file, p.Title, name)
					}
				}
			}
		}
	}
}
