package probe

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
)

// quoted builds the payload a router puts inside a time-exceeded message: the
// header of the datagram it dropped, followed by the start of that datagram.
func quoted(seq int, v6 bool) []byte {
	header := []byte{0x45} // IPv4, header length 5 words
	header = append(header, make([]byte, 19)...)
	if v6 {
		header = make([]byte, 40) // fixed length, no options
	}
	echo := make([]byte, 8) // type, code, checksum, id, seq
	binary.BigEndian.PutUint16(echo[6:8], uint16(seq))
	return append(header, echo...)
}

// Hops are matched on the sequence number: the kernel rewrites the identifier
// on an unprivileged socket but leaves the sequence alone.
func TestQuotedSeq(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, seq := range []int{1, 7, 30, 65535} {
			if got := quotedSeq(quoted(seq, v6), v6); got != seq {
				t.Errorf("v6=%v seq=%d: got %d", v6, seq, got)
			}
		}
	}

	// An IPv4 header carrying options is longer, and the sequence moves with it.
	withOptions := quoted(9, false)
	withOptions[0] = 0x46 // six words
	withOptions = append(withOptions[:24], withOptions[20:]...)
	if got := quotedSeq(withOptions, false); got != 9 {
		t.Errorf("options in the quoted header: got %d, want 9", got)
	}

	// A truncated quote must not read past the end of the buffer.
	for _, short := range [][]byte{nil, {0x45}, make([]byte, 24)} {
		if got := quotedSeq(short, false); got != -1 && got != 0 {
			t.Errorf("truncated quote returned %d", got)
		}
	}
	if got := quotedSeq(make([]byte, 4), true); got != -1 {
		t.Errorf("truncated IPv6 quote returned %d", got)
	}
}

// The fingerprint is what turns a reroute into a counter increment, so it must
// change when the route does and hold steady when it does not.
func TestPathFingerprint(t *testing.T) {
	hop := func(addr string) Hop {
		if addr == "" {
			return Hop{RTT: time.Millisecond}
		}
		return Hop{IP: netip.MustParseAddr(addr), RTT: time.Millisecond}
	}

	base := Path{Hops: []Hop{hop("192.168.1.1"), hop(""), hop("203.0.113.1")}}
	same := Path{Hops: []Hop{hop("192.168.1.1"), hop(""), hop("203.0.113.1")}}
	if base.Fingerprint() != same.Fingerprint() {
		t.Fatal("the same route must fingerprint the same")
	}

	rerouted := Path{Hops: []Hop{hop("192.168.1.1"), hop(""), hop("198.51.100.1")}}
	shorter := Path{Hops: []Hop{hop("192.168.1.1"), hop("")}}
	for name, p := range map[string]Path{"rerouted": rerouted, "shorter": shorter} {
		if p.Fingerprint() == base.Fingerprint() {
			t.Errorf("%s: fingerprint did not change", name)
		}
	}

	// A hop that answers this time but not the next is a rate limit, not a
	// reroute, and would otherwise flood the change counter.
	if got := base.Fingerprint(); got != "192.168.1.1 * 203.0.113.1" {
		t.Fatalf("fingerprint = %q", got)
	}
}

// The loopback is one hop away and always answers, so a trace to it must come
// back complete after a single step. Skipped where the platform will not hand
// out an ICMP socket without privileges, which is the usual case on a
// developer machine and on a locked down runner.
func TestTraceLoopback(t *testing.T) {
	tr := Tracer{MaxHops: 5, Timeout: time.Second}
	dst := netip.MustParseAddr("127.0.0.1")

	if conn, err := icmp.ListenPacket(tr.network(false), tr.listenAddr(false)); err != nil {
		t.Skipf("no unprivileged ICMP socket here: %v", err)
	} else {
		conn.Close()
	}

	path, err := tr.Trace(dst)
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	if !path.Complete || len(path.Hops) != 1 {
		t.Fatalf("loopback should be one complete hop, got %+v", path)
	}
	if path.Hops[0].IP != dst {
		t.Fatalf("hop 1 = %s, want %s", path.Hops[0].IP, dst)
	}
}

func TestTracerNetwork(t *testing.T) {
	priv := Tracer{Privileged: true}
	unpriv := Tracer{}
	cases := map[string]string{
		priv.network(false):   "ip4:icmp",
		priv.network(true):    "ip6:ipv6-icmp",
		unpriv.network(false): "udp4",
		unpriv.network(true):  "udp6",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("network = %q, want %q", got, want)
		}
	}
	if icmpProtocol(false) != 1 || icmpProtocol(true) != 58 {
		t.Error("ICMP protocol numbers must be the IANA ones")
	}
}
