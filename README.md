# netprobe-exporter

[![CI](https://github.com/Arylite/netprobe-exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/Arylite/netprobe-exporter/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Arylite/netprobe-exporter)](https://goreportcard.com/report/github.com/Arylite/netprobe-exporter)

A Prometheus exporter that continuously probes a list of hosts over ICMP, TCP and UDP
and reports round-trip time, packet loss and jitter, with arbitrary labels per target.

It fills the gap between `blackbox_exporter`, which probes once per scrape and therefore
cannot measure loss or jitter, and `ping_exporter`, which measures both but only over
ICMP. Probing runs in the background on its own schedule, so a slow or failed scrape
never disturbs the measurement cadence.

## Metrics

Every probe metric carries `name`, `host`, `proto` and `port`, plus the labels defined
for that target.

| Metric | Type | Description |
| --- | --- | --- |
| `netprobe_probe_success` | gauge | `1` if the last cycle received at least one reply |
| `netprobe_rtt_seconds` | gauge | Mean round-trip time of the last cycle |
| `netprobe_rtt_min_seconds` | gauge | Minimum round-trip time of the last cycle |
| `netprobe_rtt_max_seconds` | gauge | Maximum round-trip time of the last cycle |
| `netprobe_rtt_stddev_seconds` | gauge | Round-trip time standard deviation, i.e. jitter |
| `netprobe_loss_ratio` | gauge | Fraction of the last cycle's samples with no reply |
| `netprobe_packets_sent_total` | counter | Samples sent |
| `netprobe_packets_received_total` | counter | Samples answered |
| `netprobe_last_probe_timestamp_seconds` | gauge | Unix time of the last completed cycle |
| `netprobe_resolved_ip_info` | gauge | Address the target currently resolves to |
| `netprobe_build_info` | gauge | Version, revision and Go version |

When a cycle receives no reply at all, the round-trip time gauges are set to `NaN`
rather than keeping their previous value, so dashboards render a gap instead of a
flat line.

The counters let loss be computed over any window, independently of the configured
probe interval:

```promql
1 - rate(netprobe_packets_received_total[5m]) / rate(netprobe_packets_sent_total[5m])
```

## Quick start

```sh
docker run -d --name netprobe \
  -p 9427:9427 \
  -v "$PWD/netprobe.yml:/etc/netprobe/netprobe.yml:ro" \
  ghcr.io/arylite/netprobe-exporter:latest

curl -s localhost:9427/metrics | grep netprobe_
```

Scrape it with a plain static config. No relabeling or multi-target pattern is needed,
because the target labels are carried by the exporter itself:

```yaml
scrape_configs:
  - job_name: netprobe
    scrape_interval: 15s
    static_configs:
      - targets: ["netprobe:9427"]
```

Keep `scrape_interval` at or below the smallest probe `interval`, otherwise completed
cycles are measured but never sampled.

## Configuration

```yaml
listen: ":9427"
privileged: true # raw ICMP sockets

defaults:
  interval: 15s # one probing cycle per target and protocol
  timeout: 2s # per sample
  count: 5 # samples per cycle

targets:
  - name: cloudflare-dns
    host: 1.1.1.1
    labels: { scope: internet, provider: cloudflare }
    probes: [icmp, "tcp:443"]

  - name: example-site
    host: www.example.com
    labels: { scope: internet }
    probes: [icmp, "tcp:443"]
    interval: 10s # overrides the default for this target
```

| Key | Scope | Default | Description |
| --- | --- | --- | --- |
| `listen` | global | `:9427` | Address the HTTP server binds to |
| `privileged` | global | `true` | Use raw ICMP sockets |
| `defaults.interval` | global | `15s` | Delay between cycles |
| `defaults.timeout` | global | `2s` | Per-sample timeout |
| `defaults.count` | global | `5` | Samples per cycle |
| `name` | target | value of `host` | Series identity |
| `host` | target | required | IP address or hostname |
| `probes` | target | required | `icmp`, `tcp:<port>`, `udp:<port>` |
| `labels` | target | none | Free-form labels added to every metric |
| `payload` | target | `00` | Hex-encoded UDP payload |
| `interval`, `timeout`, `count` | target | from `defaults` | Per-target overrides |

Label keys are collected across all targets and the union is applied to every series,
with an empty value where a target does not define a key. Prometheus requires a
consistent label set per metric, so this is what allows targets to carry different
labels. Unknown configuration keys are rejected at startup rather than ignored.

Hostnames are resolved on every cycle. `netprobe_resolved_ip_info` reports the address
that was actually probed, which identifies the point of presence answering for an
anycast or CDN name.

## Probe behaviour

**ICMP** — echo request and reply through
[pro-bing](https://github.com/prometheus-community/pro-bing), sending `count` packets
spaced 100 ms apart.

**TCP** — `connect()` to the port. The call returns when the SYN-ACK arrives, so the
measurement is the SYN to SYN-ACK delta plus a few hundred microseconds of scheduler
overhead. The connection is closed with RST rather than FIN to avoid accumulating
TIME_WAIT sockets. A closed or filtered port counts as a loss.

**UDP** — one datagram on a connected socket, then a read with a deadline:

- an application reply means the host answered;
- `ECONNREFUSED`, which is how the kernel surfaces an ICMP port unreachable message,
  means the host was reached and the port is closed;
- a timeout counts as a loss.

Two caveats apply to UDP. A port that is open but silent looks like 100% loss, so set
`payload` to a request the service will answer. And against a closed port, Linux
rate-limits ICMP unreachable messages to roughly one per second, so use `count: 1` for
those targets or the exporter measures the rate limit rather than the network.

## Running without CAP_NET_RAW

The image sets the `cap_net_raw` file capability on the binary and runs as an
unprivileged user. CAP_NET_RAW belongs to the default Docker capability set, so raw
ICMP works out of the box.

Where the capability is unavailable, switch to unprivileged ICMP:

```yaml
# netprobe.yml
privileged: false
```

```yaml
# docker-compose.yml
sysctls:
  net.ipv4.ping_group_range: "0 2147483647"
```

## Prometheus and Grafana example

[`examples/docker-compose`](examples/docker-compose) contains a complete stack: the
exporter, Prometheus, and Grafana with a provisioned data source and dashboard.

```sh
cd examples/docker-compose
docker compose up -d
```

Grafana is then available on <http://localhost:3000> with the default `admin` /
`admin` credentials, and the dashboard is preloaded in the Network folder.

## Development

```sh
go test ./...
go vet ./...
```

Adding a protocol means implementing `Prober` in `probe.go`, which is a single
`Probe(host, count, timeout) Result` method, then adding a case to `parseProbe` and
`newProber`.

## License

Apache License 2.0. See [LICENSE](LICENSE).
