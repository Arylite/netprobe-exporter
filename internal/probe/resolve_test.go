package probe

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Arylite/netprobe-exporter/internal/config"
)

// A literal address must not cost a lookup, and must not be reported as one:
// netprobe_dns_lookup_seconds would otherwise read zero for every IP target
// and drag the average down.
func TestResolveLiteral(t *testing.T) {
	for _, host := range []string{"192.0.2.10", "2001:db8::1"} {
		res := Resolve(host, config.FamilyAuto, time.Second)
		if res.Err != nil {
			t.Fatalf("%s: %v", host, res.Err)
		}
		if res.Looked {
			t.Fatalf("%s: a literal address needs no resolver", host)
		}
		if res.IP.String() != host {
			t.Fatalf("%s: got %s", host, res.IP)
		}
	}

	// Pinning the wrong family for a literal is a configuration mistake and
	// must not silently probe the other one.
	if res := Resolve("192.0.2.10", config.FamilyIPv6, time.Second); res.Err == nil {
		t.Fatal("an IPv4 literal cannot be probed as IPv6")
	}
	if res := Resolve("2001:db8::1", config.FamilyIPv4, time.Second); res.Err == nil {
		t.Fatal("an IPv6 literal cannot be probed as IPv4")
	}
}

func TestFamilyMatching(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.10")
	v6 := netip.MustParseAddr("2001:db8::1")
	mapped := netip.MustParseAddr("::ffff:192.0.2.10")

	cases := []struct {
		f          config.Family
		addr       netip.Addr
		want       bool
		wantFamily config.Family
	}{
		{config.FamilyAuto, v4, true, config.FamilyIPv4},
		{config.FamilyAuto, v6, true, config.FamilyIPv6},
		{config.FamilyIPv4, v4, true, config.FamilyIPv4},
		{config.FamilyIPv4, v6, false, config.FamilyIPv6},
		{config.FamilyIPv6, v6, true, config.FamilyIPv6},
		{config.FamilyIPv6, v4, false, config.FamilyIPv4},
		// A v4-mapped address is IPv4 on the wire, whatever its notation.
		{config.FamilyIPv4, mapped, true, config.FamilyIPv4},
		{config.FamilyIPv6, mapped, false, config.FamilyIPv4},
	}
	for _, c := range cases {
		if got := c.f.Matches(c.addr); got != c.want {
			t.Errorf("%q.Matches(%s) = %v, want %v", c.f, c.addr, got, c.want)
		}
		if got := config.FamilyOf(c.addr); got != c.wantFamily {
			t.Errorf("config.FamilyOf(%s) = %q, want %q", c.addr, got, c.wantFamily)
		}
	}

	// The resolver network names must be the ones Go understands.
	for f, want := range map[config.Family]string{config.FamilyAuto: "ip", config.FamilyIPv4: "ip4", config.FamilyIPv6: "ip6"} {
		if got := f.Network(); got != want {
			t.Errorf("%q.Network() = %q, want %q", f, got, want)
		}
	}
}

// A name that cannot resolve is a failed cycle, not a hang.
func TestResolveFailure(t *testing.T) {
	// .invalid is reserved by RFC 2606 and never resolves.
	res := Resolve("netprobe.invalid", config.FamilyAuto, 5*time.Second)
	if res.Err == nil {
		t.Fatalf("expected a failure, got %s", res.IP)
	}
	if !res.Looked {
		t.Fatal("a failed lookup is still a lookup and must be timed")
	}
}
