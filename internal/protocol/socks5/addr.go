package socks5

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
)

// Addr is a SOCKS5 address:
//
//	+------+----------+----------+
//	| ATYP |   ADDR   |   PORT   |
//	+------+----------+----------+
//	|  1   | Variable |    2     |
//	+------+----------+----------+
type Addr struct {
	Type byte
	Host string
	Port uint16
}

// NewAddr parses a "host:port" string into an Addr, inferring the type.
func NewAddr(saddr string) (*Addr, error) {
	addr := &Addr{}
	if err := addr.ParseFrom(saddr); err != nil {
		return nil, err
	}
	return addr, nil
}

// ParseFrom fills the address from a "host:port" string and infers Type.
func (addr *Addr) ParseFrom(saddr string) error {
	host, sport, err := net.SplitHostPort(saddr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(sport)
	if err != nil {
		return err
	}
	addr.Host = host
	addr.Port = uint16(port)
	addr.checkType()
	return nil
}

// readBody reads the address body for the already-set Type (no ATYP). It is
// shared by the request and reply decoders.
func (addr *Addr) readBody(r io.Reader) (int64, error) {
	var n int64

	switch addr.Type {
	case AddrIPv4:
		ip := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, ip); err != nil {
			return 0, err
		}
		addr.Host = net.IP(ip).String()
		n = net.IPv4len
	case AddrIPv6:
		ip := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, ip); err != nil {
			return 0, err
		}
		addr.Host = net.IP(ip).String()
		n = net.IPv6len
	case AddrDomain:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return 0, err
		}
		addrlen := int(length[0])
		n = 1
		if addrlen > 0 {
			name := make([]byte, addrlen)
			if _, err := io.ReadFull(r, name); err != nil {
				return n, err
			}
			addr.Host = string(name)
			n += int64(addrlen)
		}
	default:
		return 0, ErrBadAddrType
	}

	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return n, err
	}
	addr.Port = binary.BigEndian.Uint16(port[:])
	return n + 2, nil
}

// Decode parses an address from b and returns the number of bytes consumed.
func (addr *Addr) Decode(b []byte) (int, error) {
	if len(b) < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	addr.Type = b[0]
	n := 1

	switch addr.Type {
	case AddrIPv4:
		if len(b) < n+net.IPv4len+2 {
			return 0, io.ErrUnexpectedEOF
		}
		addr.Host = net.IP(b[n : n+net.IPv4len]).String()
		n += net.IPv4len
	case AddrIPv6:
		if len(b) < n+net.IPv6len+2 {
			return 0, io.ErrUnexpectedEOF
		}
		addr.Host = net.IP(b[n : n+net.IPv6len]).String()
		n += net.IPv6len
	case AddrDomain:
		if len(b) < n+1 {
			return 0, io.ErrUnexpectedEOF
		}
		addrlen := int(b[n])
		n++
		if len(b) < n+addrlen+2 {
			return 0, io.ErrUnexpectedEOF
		}
		addr.Host = string(b[n : n+addrlen])
		n += addrlen
	default:
		return 0, ErrBadAddrType
	}

	addr.Port = binary.BigEndian.Uint16(b[n:])
	return n + 2, nil
}

// Encode writes the wire representation into b and returns its length. b must
// be at least Length() bytes long.
func (addr *Addr) Encode(b []byte) (int, error) {
	addr.checkType()

	b[0] = addr.Type
	pos := 1

	switch addr.Type {
	case AddrIPv4:
		ip := net.ParseIP(addr.Host).To4()
		if ip == nil {
			ip = net.IPv4zero.To4()
		}
		pos += copy(b[pos:], ip)
	case AddrIPv6:
		ip := net.ParseIP(addr.Host).To16()
		if ip == nil {
			ip = net.IPv6zero.To16()
		}
		pos += copy(b[pos:], ip)
	case AddrDomain:
		if len(addr.Host) == 0 || len(addr.Host) > 255 {
			return 0, ErrBadFormat
		}
		b[pos] = byte(len(addr.Host))
		pos++
		pos += copy(b[pos:], addr.Host)
	}

	binary.BigEndian.PutUint16(b[pos:], addr.Port)
	return pos + 2, nil
}

// checkType fills in Type when it has not been set, choosing the most
// specific representation for Host.
func (addr *Addr) checkType() {
	switch addr.Type {
	case AddrIPv4, AddrIPv6, AddrDomain:
		return
	}
	addr.Type = AddrIPv4
	if addr.Host == "" {
		return
	}
	addr.Type = AddrDomain
	if ip := net.ParseIP(addr.Host); ip != nil {
		if ip.To4() != nil {
			addr.Type = AddrIPv4
		} else {
			addr.Type = AddrIPv6
		}
	}
}

// Length returns the encoded length of the address in bytes.
func (addr *Addr) Length() int {
	addr.checkType()
	switch addr.Type {
	case AddrIPv4:
		return 7
	case AddrIPv6:
		return 19
	case AddrDomain:
		return 4 + len(addr.Host)
	default:
		return 0
	}
}

// String returns "host:port", bracketing IPv6 hosts.
func (addr *Addr) String() string {
	if addr == nil {
		return ""
	}
	return net.JoinHostPort(addr.Host, strconv.Itoa(int(addr.Port)))
}
