package probe

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// STUN binding request, RFC 5389. Twenty bytes out, one datagram back, no
// dependency and no HTTP: enough to learn the address the far side sees.
const (
	stunBindingRequest  = 0x0001
	stunBindingResponse = 0x0101
	stunMagicCookie     = 0x2112a442
	stunHeaderLen       = 20

	attrMappedAddress    = 0x0001
	attrXORMappedAddress = 0x0020
)

// cgnat is the shared address space of RFC 6598. A local address inside it
// means the operator, not the subscriber, is doing the translation.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// WANAddress is what the outside world sees of this host.
type WANAddress struct {
	Public netip.Addr // address the STUN server replied about
	Local  netip.Addr // address of the socket that sent the request
}

// BehindCGNAT reports whether the operator placed this host behind a carrier
// grade NAT. It can only tell when the exporter itself holds the WAN address,
// which is the case on a router or a CPE; from a host on a private LAN the
// local address is the LAN one and the answer is always false.
func (w WANAddress) BehindCGNAT() bool {
	return w.Local.IsValid() && cgnat.Contains(w.Local)
}

// QueryWAN asks a STUN server which address this host appears to come from.
// Watching it change is how a client sees its own access link reconnect: a
// PPPoE session that drops at 4am comes back with a different address, and
// nothing else on the client side records that it happened.
func QueryWAN(server string, timeout time.Duration) (WANAddress, error) {
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return WANAddress{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return WANAddress{}, err
	}

	req := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(req[2:4], 0) // no attributes
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	if _, err := rand.Read(req[8:20]); err != nil {
		return WANAddress{}, err
	}
	if _, err := conn.Write(req); err != nil {
		return WANAddress{}, err
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return WANAddress{}, err
	}
	public, err := parseSTUN(buf[:n], req[8:20])
	if err != nil {
		return WANAddress{}, err
	}

	var local netip.Addr
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		local, _ = netip.AddrFromSlice(ua.IP)
		local = local.Unmap()
	}
	return WANAddress{Public: public, Local: local}, nil
}

// parseSTUN extracts the mapped address from a binding response, checking that
// it answers the transaction we started rather than a stray datagram.
func parseSTUN(msg, txID []byte) (netip.Addr, error) {
	if len(msg) < stunHeaderLen {
		return netip.Addr{}, errors.New("stun: response too short")
	}
	if t := binary.BigEndian.Uint16(msg[0:2]); t != stunBindingResponse {
		return netip.Addr{}, fmt.Errorf("stun: unexpected message type %#04x", t)
	}
	if binary.BigEndian.Uint32(msg[4:8]) != stunMagicCookie {
		return netip.Addr{}, errors.New("stun: bad magic cookie")
	}
	if string(msg[8:20]) != string(txID) {
		return netip.Addr{}, errors.New("stun: transaction id mismatch")
	}

	body := msg[stunHeaderLen:]
	if n := int(binary.BigEndian.Uint16(msg[2:4])); n <= len(body) {
		body = body[:n]
	}

	for len(body) >= 4 {
		typ := binary.BigEndian.Uint16(body[0:2])
		length := int(binary.BigEndian.Uint16(body[2:4]))
		if len(body) < 4+length {
			break
		}
		value := body[4 : 4+length]

		switch typ {
		case attrXORMappedAddress:
			return decodeAddress(value, txID, true)
		case attrMappedAddress:
			// Only used by pre-RFC 5389 servers, and only if no XOR attribute
			// showed up first; keeping it costs three lines.
			if addr, err := decodeAddress(value, txID, false); err == nil {
				return addr, nil
			}
		}
		// Attribute values are padded to a four byte boundary.
		body = body[4+(length+3)&^3:]
	}
	return netip.Addr{}, errors.New("stun: no mapped address in response")
}

// decodeAddress reads a MAPPED-ADDRESS value: a reserved byte, a family, a
// port and the address. The XOR variant masks both with the magic cookie so
// that a NAT rewriting payloads cannot mangle them by accident.
func decodeAddress(v, txID []byte, xor bool) (netip.Addr, error) {
	if len(v) < 8 {
		return netip.Addr{}, errors.New("stun: address attribute too short")
	}
	size := 4
	if v[1] == 0x02 {
		size = 16
	} else if v[1] != 0x01 {
		return netip.Addr{}, fmt.Errorf("stun: unknown address family %#02x", v[1])
	}
	if len(v) < 4+size {
		return netip.Addr{}, errors.New("stun: truncated address")
	}

	raw := make([]byte, size)
	copy(raw, v[4:4+size])
	if xor {
		var mask [20]byte
		binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
		copy(mask[4:], txID)
		for i := range raw {
			raw[i] ^= mask[i]
		}
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, errors.New("stun: malformed address")
	}
	return addr.Unmap(), nil
}
