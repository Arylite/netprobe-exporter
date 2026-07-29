package probe

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// stunResponse builds a binding response carrying addr, so the parser is
// tested against the wire format rather than against itself.
func stunResponse(t *testing.T, txID []byte, addr netip.Addr, xor bool) []byte {
	t.Helper()

	raw := addr.AsSlice()
	family := byte(0x01)
	if len(raw) == 16 {
		family = 0x02
	}
	port := []byte{0x1f, 0x40} // 8000

	if xor {
		var mask [20]byte
		binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
		copy(mask[4:], txID)
		for i := range raw {
			raw[i] ^= mask[i]
		}
		port[0] ^= mask[0]
		port[1] ^= mask[1]
	}

	value := append([]byte{0x00, family, port[0], port[1]}, raw...)
	attr := make([]byte, 4)
	typ := uint16(attrMappedAddress)
	if xor {
		typ = attrXORMappedAddress
	}
	binary.BigEndian.PutUint16(attr[0:2], typ)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(value)))
	attr = append(attr, value...)

	msg := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(msg[0:2], stunBindingResponse)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txID)
	return append(msg, attr...)
}

func TestParseSTUN(t *testing.T) {
	txID := []byte("0123456789ab")

	for _, addr := range []string{"203.0.113.7", "2001:db8::dead:beef"} {
		want := netip.MustParseAddr(addr)
		for _, xor := range []bool{true, false} {
			got, err := parseSTUN(stunResponse(t, txID, want, xor), txID)
			if err != nil {
				t.Fatalf("%s (xor=%v): %v", addr, xor, err)
			}
			if got != want {
				t.Fatalf("%s (xor=%v): got %s", addr, xor, got)
			}
		}
	}
}

// The response arrives on a socket anything can write to, so every field that
// proves it belongs to our transaction has to be checked.
func TestParseSTUNRejectsBadInput(t *testing.T) {
	txID := []byte("0123456789ab")
	good := stunResponse(t, txID, netip.MustParseAddr("203.0.113.7"), true)

	corrupt := map[string]func([]byte) []byte{
		"truncated header":   func(b []byte) []byte { return b[:8] },
		"wrong message type": func(b []byte) []byte { b[1] = 0x02; return b },
		"bad magic cookie":   func(b []byte) []byte { b[4] ^= 0xff; return b },
		"foreign transation": func(b []byte) []byte { b[10] ^= 0xff; return b },
		"no attributes":      func(b []byte) []byte { return b[:stunHeaderLen] },
		"truncated address":  func(b []byte) []byte { return b[:len(b)-4] },
	}
	for name, corruptFn := range corrupt {
		msg := corruptFn(append([]byte{}, good...))
		if _, err := parseSTUN(msg, txID); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestBehindCGNAT(t *testing.T) {
	cases := map[string]bool{
		"100.64.0.1":    true, // RFC 6598 shared address space
		"100.127.255.1": true,
		"100.128.0.1":   false, // just outside the /10
		"100.63.255.1":  false,
		"192.168.1.10":  false, // a LAN address says nothing either way
		"203.0.113.7":   false,
	}
	for addr, want := range cases {
		w := WANAddress{Public: netip.MustParseAddr("203.0.113.7"), Local: netip.MustParseAddr(addr)}
		if got := w.BehindCGNAT(); got != want {
			t.Errorf("local %s: BehindCGNAT = %v, want %v", addr, got, want)
		}
	}
	if (WANAddress{}).BehindCGNAT() {
		t.Error("an unknown local address is not a CGNAT verdict")
	}
}
