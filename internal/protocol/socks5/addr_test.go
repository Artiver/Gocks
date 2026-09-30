package socks5

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestAddrRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		addr *Addr
	}{
		{"ipv4", &Addr{Type: AddrIPv4, Host: "1.2.3.4", Port: 80}},
		{"ipv6", &Addr{Type: AddrIPv6, Host: "2001:db8::1", Port: 443}},
		{"domain", &Addr{Type: AddrDomain, Host: "example.com", Port: 8080}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, tc.addr.Length())
			n, err := tc.addr.Encode(buf)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if n != len(buf) {
				t.Fatalf("Encode wrote %d bytes, Length()=%d", n, len(buf))
			}

			var got Addr
			dn, err := got.Decode(buf[:n])
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if dn != n {
				t.Fatalf("Decode consumed %d, want %d", dn, n)
			}
			if got.Type != tc.addr.Type || got.Host != tc.addr.Host || got.Port != tc.addr.Port {
				t.Fatalf("round trip mismatch: got %+v want %+v", got, tc.addr)
			}
		})
	}
}

func TestAddrCheckType(t *testing.T) {
	cases := []struct {
		host string
		want byte
	}{
		{"", AddrIPv4},
		{"1.2.3.4", AddrIPv4},
		{"::1", AddrIPv6},
		{"example.com", AddrDomain},
	}
	for _, tc := range cases {
		addr := &Addr{Host: tc.host, Port: 1}
		addr.checkType()
		if addr.Type != tc.want {
			t.Fatalf("host %q: got type %d want %d", tc.host, addr.Type, tc.want)
		}
	}
}

func TestAddrZeroEncodesAsIPv4(t *testing.T) {
	// A nil/zero address must still serialize to a valid ATYP=IPv4 address,
	// which is what replies use when no bound address is meaningful.
	addr := &Addr{}
	buf := make([]byte, addr.Length())
	n, err := addr.Encode(buf)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{AddrIPv4, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("got %v want %v", buf[:n], want)
	}
}

func TestAddrParseFrom(t *testing.T) {
	addr, err := NewAddr("example.com:1080")
	if err != nil {
		t.Fatalf("NewAddr: %v", err)
	}
	if addr.Type != AddrDomain || addr.Host != "example.com" || addr.Port != 1080 {
		t.Fatalf("unexpected addr: %+v", addr)
	}

	if _, err := NewAddr("no-port"); err == nil {
		t.Fatal("want error for missing port")
	}
}

func TestAddrString(t *testing.T) {
	ipv4 := &Addr{Type: AddrIPv4, Host: "1.2.3.4", Port: 80}
	if got := ipv4.String(); got != "1.2.3.4:80" {
		t.Fatalf("got %q", got)
	}
	ipv6 := &Addr{Type: AddrIPv6, Host: "::1", Port: 443}
	if got := ipv6.String(); got != "[::1]:443" {
		t.Fatalf("got %q", got)
	}
}

func TestAddrDecodeShort(t *testing.T) {
	if _, err := new(Addr).Decode([]byte{AddrIPv4, 1, 2}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want ErrUnexpectedEOF, got %v", err)
	}
}

func TestAddrDecodeBadType(t *testing.T) {
	if _, err := new(Addr).Decode([]byte{0x02, 0, 0, 0}); !errors.Is(err, ErrBadAddrType) {
		t.Fatalf("want ErrBadAddrType, got %v", err)
	}
}

func TestAddrDecodeDomainEmpty(t *testing.T) {
	// ATYP=domain, length=0, port=80.
	wire := []byte{AddrDomain, 0x00, 0x00, 0x50}
	var addr Addr
	if _, err := addr.Decode(wire); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if addr.Type != AddrDomain || addr.Host != "" || addr.Port != 80 {
		t.Fatalf("unexpected addr: %+v", addr)
	}
}

func TestAddrFragmented(t *testing.T) {
	// The address body is read through readBody by the request and reply
	// decoders, so a reader that hands over one byte at a time must still
	// produce a complete address.
	addr := &Addr{Type: AddrDomain, Host: "fragmented.example", Port: 53}
	buf := make([]byte, addr.Length())
	n, err := addr.Encode(buf)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	wire := append([]byte{Version, CmdConnect, 0x00}, buf[:n]...)

	req, err := ReadRequest(&oneByteReader{data: wire})
	if err != nil {
		t.Fatalf("ReadRequest fragmented: %v", err)
	}
	if req.Addr.Host != addr.Host || req.Addr.Port != addr.Port {
		t.Fatalf("got %+v want %+v", req.Addr, addr)
	}
}
