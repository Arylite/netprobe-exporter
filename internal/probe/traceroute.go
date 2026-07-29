package probe

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/Arylite/netprobe-exporter/internal/config"
)

// Hop is one step of the path towards a target. A hop that did not answer
// keeps the zero address: routers that drop ICMP or rate-limit it are normal
// and do not mean the path is broken.
type Hop struct {
	IP  netip.Addr
	RTT time.Duration
}

// Path is the outcome of one traceroute cycle.
type Path struct {
	Hops     []Hop
	Complete bool // the destination itself answered, so the path is whole
}

// Fingerprint identifies the route taken, so a change can be detected without
// keeping a series per hop address. Silent hops are folded into "*", which
// means a router that answers intermittently does not read as a reroute.
func (p Path) Fingerprint() string {
	parts := make([]string, len(p.Hops))
	for i, h := range p.Hops {
		if h.IP.IsValid() {
			parts[i] = h.IP.String()
		} else {
			parts[i] = "*"
		}
	}
	return strings.Join(parts, " ")
}

// Tracer walks the path to a destination with TTL-limited echo requests.
//
// pro-bing cannot do this: it drops every reply that is not an echo reply,
// and a traceroute is built out of the time-exceeded messages the routers on
// the way send back. The socket is the same kind pro-bing uses, so the
// privileged flag and its capability requirement carry over unchanged.
type Tracer struct {
	Privileged bool
	MaxHops    int
	Timeout    time.Duration
}

// Trace probes hop by hop, in order, stopping at the destination. Sequential
// probing keeps the reply matching trivial and bounds the cost at maxHops
// times the timeout, which is why traceroute runs on its own slow interval.
func (t Tracer) Trace(dst netip.Addr) (Path, error) {
	v6 := config.FamilyOf(dst) == config.FamilyIPv6

	conn, err := icmp.ListenPacket(t.network(v6), t.listenAddr(v6))
	if err != nil {
		return Path{}, err
	}
	defer conn.Close()

	// The kernel rewrites the identifier on an unprivileged socket, so hops
	// are matched on the sequence number, which it leaves alone.
	id := os.Getpid() & 0xffff

	var p Path
	for ttl := 1; ttl <= t.MaxHops; ttl++ {
		hop, arrived, err := t.probeHop(conn, dst, v6, id, ttl)
		if err != nil {
			return p, err
		}
		p.Hops = append(p.Hops, hop)
		if arrived {
			p.Complete = true
			break
		}
	}
	return p, nil
}

func (t Tracer) network(v6 bool) string {
	switch {
	case v6 && t.Privileged:
		return "ip6:ipv6-icmp"
	case v6:
		return "udp6"
	case t.Privileged:
		return "ip4:icmp"
	default:
		return "udp4"
	}
}

func (t Tracer) listenAddr(v6 bool) string {
	if v6 {
		return "::"
	}
	return "0.0.0.0"
}

// probeHop sends one echo request with the given TTL and waits for whatever
// comes back. A timeout is not an error: it is a silent hop.
func (t Tracer) probeHop(conn *icmp.PacketConn, dst netip.Addr, v6 bool, id, ttl int) (Hop, bool, error) {
	if v6 {
		if err := conn.IPv6PacketConn().SetHopLimit(ttl); err != nil {
			return Hop{}, false, err
		}
	} else {
		if err := conn.IPv4PacketConn().SetTTL(ttl); err != nil {
			return Hop{}, false, err
		}
	}

	echo := icmp.Message{
		Type: icmp.Type(ipv4.ICMPTypeEcho),
		Body: &icmp.Echo{ID: id, Seq: ttl, Data: []byte("netprobe")},
	}
	if v6 {
		echo.Type = ipv6.ICMPTypeEchoRequest
	}
	raw, err := echo.Marshal(nil)
	if err != nil {
		return Hop{}, false, err
	}

	var dest net.Addr = &net.IPAddr{IP: dst.AsSlice()}
	if !t.Privileged {
		dest = &net.UDPAddr{IP: dst.AsSlice()}
	}

	start := time.Now()
	if _, err := conn.WriteTo(raw, dest); err != nil {
		return Hop{}, false, err
	}
	if err := conn.SetReadDeadline(start.Add(t.Timeout)); err != nil {
		return Hop{}, false, err
	}

	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return Hop{}, false, nil // deadline reached: the hop stayed silent
		}
		rtt := time.Since(start)

		reply, err := icmp.ParseMessage(icmpProtocol(v6), buf[:n])
		if err != nil {
			continue
		}
		switch body := reply.Body.(type) {
		case *icmp.TimeExceeded:
			// The router quotes the datagram it dropped; the sequence number
			// inside says which of our probes it belongs to.
			if quotedSeq(body.Data, v6) == ttl {
				return Hop{IP: peerAddr(peer), RTT: rtt}, false, nil
			}
		case *icmp.Echo:
			if body.Seq == ttl {
				return Hop{IP: peerAddr(peer), RTT: rtt}, true, nil
			}
		}
	}
}

// icmpProtocol is the IANA protocol number ParseMessage needs to know which
// ICMP dialect it is looking at.
func icmpProtocol(v6 bool) int {
	if v6 {
		return 58
	}
	return 1
}

// quotedSeq digs the sequence number out of the original datagram a router
// quotes back inside a time-exceeded message: an IP header followed by the
// first bytes of the ICMP echo, whose sequence sits at offset 6.
func quotedSeq(data []byte, v6 bool) int {
	header := 40 // IPv6 headers are fixed length
	if !v6 {
		if len(data) < 1 {
			return -1
		}
		header = int(data[0]&0x0f) * 4
	}
	if len(data) < header+8 {
		return -1
	}
	return int(binary.BigEndian.Uint16(data[header+6 : header+8]))
}

func peerAddr(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.IPAddr:
		addr, _ := netip.AddrFromSlice(v.IP)
		return addr.Unmap()
	case *net.UDPAddr:
		addr, _ := netip.AddrFromSlice(v.IP)
		return addr.Unmap()
	}
	return netip.Addr{}
}
