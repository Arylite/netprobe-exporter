// Package probe measures one target: the round-trip timings of a cycle of
// samples, the route taken to get there, and the address the outside world
// sees for the host doing the measuring.
package probe

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/Arylite/netprobe-exporter/internal/config"
)

// Resolution is the outcome of one name lookup.
type Resolution struct {
	IP      netip.Addr
	Latency time.Duration
	Looked  bool // false when the host was already a literal address
	Err     error
}

// Resolve turns a target host into the address to probe, timing the lookup.
//
// Names are resolved once per cycle rather than once per sample: the probers
// are handed a literal, so a cycle of count samples costs a single query
// instead of one per connect. The measured latency is what a client
// experiences before its first packet leaves, which is the usual cause of a
// "the internet is slow" report on an otherwise healthy line.
func Resolve(host string, f config.Family, timeout time.Duration) Resolution {
	if addr, err := netip.ParseAddr(host); err == nil {
		if !f.Matches(addr) {
			return Resolution{Err: fmt.Errorf("host %s is not %s", host, f)}
		}
		return Resolution{IP: addr.Unmap()}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, f.Network(), host)
	latency := time.Since(start)

	if err != nil {
		return Resolution{Latency: latency, Looked: true, Err: err}
	}
	for _, addr := range addrs {
		if f.Matches(addr) {
			return Resolution{IP: addr.Unmap(), Latency: latency, Looked: true}
		}
	}
	return Resolution{
		Latency: latency,
		Looked:  true,
		Err:     fmt.Errorf("no %s address for %s", f.Network(), host),
	}
}
