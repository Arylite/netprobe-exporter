# netprobe-exporter

[![CI](https://github.com/Arylite/netprobe-exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/Arylite/netprobe-exporter/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Arylite/netprobe-exporter)](https://goreportcard.com/report/github.com/Arylite/netprobe-exporter)

A Prometheus exporter that continuously probes a list of hosts over ICMP, TCP and UDP
and reports round-trip time, packet loss, jitter, call quality, the route taken and
the state of the access link, with arbitrary labels per target.

It fills the gap between `blackbox_exporter`, which probes once per scrape and therefore
cannot measure loss or jitter, and `ping_exporter`, which measures both but only over
ICMP. Probing runs in the background on its own schedule, so a slow or failed scrape
never disturbs the measurement cadence.

## Metrics

Every probe metric carries `name`, `host`, `proto`, `port` and `family`, plus the
labels defined for that target.

| Metric | Type | Description |
| --- | --- | --- |
| `netprobe_probe_success` | gauge | `1` if the last cycle received at least one reply |
| `netprobe_rtt_seconds` | gauge | Mean round-trip time of the last cycle |
| `netprobe_rtt_min_seconds` | gauge | Minimum round-trip time of the last cycle |
| `netprobe_rtt_max_seconds` | gauge | Maximum round-trip time of the last cycle |
| `netprobe_rtt_stddev_seconds` | gauge | Standard deviation of the cycle's samples |
| `netprobe_jitter_seconds` | gauge | RFC 3550 interarrival jitter of the last cycle |
| `netprobe_sample_rtt_seconds` | histogram | Round-trip time of every individual sample |
| `netprobe_loss_ratio` | gauge | Fraction of the last cycle's samples with no reply |
| `netprobe_mos` | gauge | Estimated mean opinion score for voice, 1 to 4.5 |
| `netprobe_r_factor` | gauge | Estimated E-model transmission rating, 0 to 100 |
| `netprobe_dns_lookup_seconds` | gauge | Time the last name resolution took |
| `netprobe_dns_failures_total` | counter | Cycles skipped because the name did not resolve |
| `netprobe_packets_sent_total` | counter | Samples sent |
| `netprobe_packets_received_total` | counter | Samples answered |
| `netprobe_last_probe_timestamp_seconds` | gauge | Unix time of the last completed cycle |
| `netprobe_resolved_ip_info` | gauge | Address the target currently resolves to |
| `netprobe_build_info` | gauge | Version, revision and Go version |

Path metrics carry `name`, `host` and `family` only, since a route belongs to a target
rather than to one of its probes. They exist for targets with `traceroute: true`.

| Metric | Type | Description |
| --- | --- | --- |
| `netprobe_path_hops` | gauge | Number of hops the last traceroute walked |
| `netprobe_path_complete` | gauge | `1` if the last traceroute reached the target |
| `netprobe_path_hop_rtt_seconds` | gauge | Round-trip time to each hop, labelled `hop` |
| `netprobe_path_hop_info` | gauge | Address answering at each hop |
| `netprobe_path_changes_total` | counter | Times the sequence of hops changed |

Access link metrics have no target labels at all. They exist when `wan.server` is set.

| Metric | Type | Description |
| --- | --- | --- |
| `netprobe_wan_ip_info` | gauge | Public address, and the local address it goes out from |
| `netprobe_wan_ip_changes_total` | counter | Times the public address changed |
| `netprobe_wan_probe_success` | gauge | `1` if the last STUN query answered |
| `netprobe_wan_behind_cgnat` | gauge | `1` if the local address is in `100.64.0.0/10` |

When a cycle receives no reply at all, the round-trip time gauges are set to `NaN`
rather than keeping their previous value, so dashboards render a gap instead of a
flat line.

The counters let loss be computed over any window, independently of the configured
probe interval:

```promql
1 - rate(netprobe_packets_received_total[5m]) / rate(netprobe_packets_sent_total[5m])
```

The gauges only ever hold the last cycle, so no quantile can be recovered from them
after the fact. `netprobe_sample_rtt_seconds` observes every individual sample and
makes latency percentiles available over any window:

```promql
histogram_quantile(0.95, sum by (le) (rate(netprobe_sample_rtt_seconds_bucket[5m])))
```

It is emitted with both classic buckets and a native histogram, so it works on any
Prometheus and carries finer detail on the versions that enable native histograms.

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

traceroute: # for the targets that opt in below
  interval: 60s
  timeout: 1s
  max_hops: 20

wan: # public address lookup; omit the block to disable it
  server: stun.l.google.com:19302
  interval: 60s

targets:
  - name: cloudflare-dns
    host: 1.1.1.1
    labels: { scope: internet, provider: cloudflare }
    probes: [icmp, "tcp:443"]
    traceroute: true # walk the route to this target

  - name: example-site
    host: www.example.com
    labels: { scope: internet }
    probes: [icmp, "tcp:443"]
    families: [ipv4, ipv6] # probe the A and the AAAA record separately
    interval: 10s # overrides the default for this target

  - name: partner-api
    host: api.example.net
    probes: ["tcp:443:50000"] # destination port 443, source port pinned to 50000
```

| Key | Scope | Default | Description |
| --- | --- | --- | --- |
| `listen` | global | `:9427` | Address the HTTP server binds to |
| `privileged` | global | `true` | Use raw ICMP sockets |
| `defaults.interval` | global | `15s` | Delay between cycles |
| `defaults.timeout` | global | `2s` | Per-sample timeout |
| `defaults.count` | global | `5` | Samples per cycle |
| `traceroute.interval` | global | `60s` | Delay between traces |
| `traceroute.timeout` | global | `1s` | Per-hop timeout |
| `traceroute.max_hops` | global | `20` | Where a trace gives up, at most 64 |
| `wan.server` | global | none | STUN server; the lookup is off until this is set |
| `wan.interval` | global | `60s` | Delay between STUN queries |
| `wan.timeout` | global | from `defaults` | STUN query timeout |
| `name` | target | value of `host` | Series identity |
| `host` | target | required | IP address or hostname |
| `probes` | target | required | `icmp`, `tcp:<port>[:<local port>]`, `udp:<port>[:<local port>]` |
| `families` | target | resolver's choice | `ipv4`, `ipv6`, or both |
| `traceroute` | target | `false` | Walk the route to this target |
| `labels` | target | none | Free-form labels added to every metric |
| `payload` | target | `00` | Hex-encoded UDP payload |
| `interval`, `timeout`, `count` | target | from `defaults` | Per-target overrides |

Label keys are collected across all targets and the union is applied to every series,
with an empty value where a target does not define a key. Prometheus requires a
consistent label set per metric, so this is what allows targets to carry different
labels. Unknown configuration keys are rejected at startup rather than ignored.

Hostnames are resolved once per cycle rather than once per sample, and the resolved
address is handed to the probers, so a cycle of five samples costs one query instead
of five. `netprobe_dns_lookup_seconds` reports how long that took, which is the delay
a client pays before its first packet leaves and never appears in a round-trip time.
`netprobe_resolved_ip_info` reports the address that was actually probed, which
identifies the point of presence answering for an anycast or CDN name.

A cycle whose name does not resolve deliberately leaves the packet counters untouched:
nothing was sent, so counting it as loss would blame the network for a resolver
problem. It shows up as `netprobe_probe_success` at `0` and an increment of
`netprobe_dns_failures_total`.

### Address families

By default a target is resolved the way any client resolves a name, and the `family`
label is empty. Listing `families: [ipv4, ipv6]` probes the A and the AAAA record as
separate series, which is what makes a broken or slow IPv6 path visible instead of
hidden behind a happy-eyeballs fallback in the application.

### Call quality

`netprobe_mos` and `netprobe_r_factor` apply the simplified ITU-T G.107 E-model to the
latency, jitter and loss the probe already measures, so they cost no extra traffic.
One-way delay is approximated as half the round trip, which breaks on an asymmetric
path; treat the score as an indicator of whether the line can hold a call, not as a
measurement of a particular call.

`netprobe_jitter_seconds` is the RFC 3550 interarrival jitter: the deviation from one
packet to the next, which is what a jitter buffer absorbs. It is reported next to
`netprobe_rtt_stddev_seconds`, the spread of the samples around their own mean, because
the two disagree in a useful way. A path that is steadily slow scores well on both; a
path that alternates between two stable latencies scores badly on both; a path that
drifts slowly has a large standard deviation and little RFC 3550 jitter.

### Traceroute

`traceroute: true` on a target walks the route with TTL-limited echo requests and
reports the round-trip time to each hop, so a slow target can be attributed to the LAN,
the access link, or something past it. Hops are probed one at a time, so a trace costs
up to `max_hops` timeouts, which is why it runs on its own slow interval.

A hop that answers nothing is normal: routers commonly drop or rate-limit ICMP. Those
hops report `NaN` rather than a missing series. `netprobe_path_changes_total` counts
reroutes, comparing the sequence of hop addresses between traces and treating a silent
hop as a wildcard so that an intermittent router does not read as a reroute.

Traceroute uses the same kind of socket as the ICMP probe, so it has the same
privilege requirement.

### Access link

Setting `wan.server` makes the exporter send a STUN binding request on that interval
and publish the address the far side sees. Watching it change is how a client notices
its own access link renegotiating: a session that drops at 4am comes back with a
different address, and nothing else on the client side records that it happened.

`netprobe_wan_behind_cgnat` is set when the local address falls in the RFC 6598 shared
range, which means the operator is translating on the subscriber's behalf. It is only
conclusive when the exporter runs on the router itself; from a host on a private LAN
the local address is the LAN one and the answer is always `0`.

The lookup is disabled unless a server is named, because it sends traffic to a third
party the operator did not necessarily choose.

### Pinning the local port

A TCP or UDP probe takes an optional third field, the local source port. The port
after the protocol is always the destination:

```yaml
probes:
  - "tcp:443" # destination 443, source port ephemeral (the default)
  - "tcp:443:50000" # destination 443, source port pinned to 50000
  - "udp:53:5353" # destination 53, source port pinned to 5353
```

Pin it when something on the path matches on the source port: a firewall rule, an
ACL, a QoS class, or a NAT mapping you want the probe to reuse rather than churn.
ICMP has no ports and rejects the field.

Pick a port outside the ephemeral range, and a different one per probe: two probes
sharing a pinned source port collide, and the loser reports the bind error as loss.
The pinned port does not appear in the metric labels, so `tcp:443` and
`tcp:443:50000` against the same target write to the same series.

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
exporter, Prometheus, and Grafana with a provisioned data source and dashboards.

```sh
cd examples/docker-compose
docker compose up -d
```

Grafana is then available on <http://localhost:3000> with the default `admin` /
`admin` credentials, and the dashboards are preloaded in the Network folder.

| Dashboard | Answers |
| --- | --- |
| netprobe | Fleet overview: round-trip time, loss and jitter across every target |
| netprobe - target drilldown | One target in detail: RTT envelope, percentiles, loss, jitter, resolution, path |
| netprobe - voice quality and latency distribution | Whether the line holds a call, and where the samples actually land |
| netprobe - path and hops | Which hop adds the latency, and when the route changed |
| netprobe - access link and name resolution | Public address, reconnections, CGNAT, and resolver latency |
| netprobe - availability and loss budget | Availability, downtime and loss over the range, scored against an objective |
| netprobe - protocol comparison | How ICMP, TCP and UDP differ against the same hosts |
| netprobe - status timeline | When each probe was up or down, and how much it flapped |
| netprobe - exporter health | Whether a flat line means a quiet network or a stalled exporter |

They are plain files under [`grafana/dashboards`](examples/docker-compose/grafana/dashboards),
picked up by the provisioning provider without any per-file configuration, and validated
by `TestDashboards` in `dashboards_test.go` so a renamed metric fails the build rather
than emptying a panel.

## Development

```sh
go test ./...
go vet ./...
```

```
cmd/netprobe-exporter   flags, registry and HTTP server
internal/config         configuration, validation and the label sets
internal/probe          ICMP, TCP and UDP probers, resolution, quality, traceroute, STUN
internal/metrics        every series, and the children each worker binds
internal/worker         the measurement loops
```

Adding a protocol means implementing `Prober` in `internal/probe`, which is a single
`Probe(host, count, timeout) Result` method, then adding a case to `config.ParseProbe`
and `probe.New`.

The dashboards are validated by `TestDashboards`, which checks every queried metric
against the registry, so a renamed metric fails the build rather than emptying a panel.
It also rejects non-ASCII bytes in the dashboard files.

## License

Apache License 2.0. See [LICENSE](LICENSE).
