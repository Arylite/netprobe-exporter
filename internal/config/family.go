package config

import "net/netip"

// Family selects the address family a target is probed over. The zero value
// lets the resolver pick, which is the behaviour of a client that simply
// connects to a name; pinning a family is what makes a broken IPv6 path
// visible instead of hidden behind a happy-eyeballs fallback.
type Family string

const (
	FamilyAuto Family = ""
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

// Network is the Go resolver network name for the family.
func (f Family) Network() string {
	switch f {
	case FamilyIPv4:
		return "ip4"
	case FamilyIPv6:
		return "ip6"
	default:
		return "ip"
	}
}

// Matches reports whether addr belongs to the family. Auto matches everything.
func (f Family) Matches(addr netip.Addr) bool {
	switch f {
	case FamilyIPv4:
		return addr.Is4() || addr.Is4In6()
	case FamilyIPv6:
		return addr.Is6() && !addr.Is4In6()
	default:
		return true
	}
}

// FamilyOf reports the family an address belongs to.
func FamilyOf(addr netip.Addr) Family {
	if addr.Is4() || addr.Is4In6() {
		return FamilyIPv4
	}
	return FamilyIPv6
}
