package socks5

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestNewAddr(t *testing.T) {
	cases := []struct {
		input    string
		wantType byte
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{"1.2.3.4:1080", AddrIPv4, "1.2.3.4", 1080, false},
		{"[::1]:1080", AddrIPv6, "::1", 1080, false},
		{"example.com:443", AddrDomain, "example.com", 443, false},
		{"256.0.0.1:80", AddrDomain, "256.0.0.1", 80, false},
		{"missing-port", 0, "", 0, true},
		{"host:notaport", 0, "", 0, true},
	}
	for _, c := range cases {
		addr, err := NewAddr(c.input)
		if c.wantErr {
			if err == nil {
				t.Errorf("NewAddr(%q) expected error, got nil", c.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("NewAddr(%q) unexpected error: %v", c.input, err)
			continue
		}
		if addr.Type != c.wantType {
			t.Errorf("NewAddr(%q).Type = %#x, want %#x", c.input, addr.Type, c.wantType)
		}
		if addr.Host != c.wantHost {
			t.Errorf("NewAddr(%q).Host = %q, want %q", c.input, addr.Host, c.wantHost)
		}
		if addr.Port != c.wantPort {
			t.Errorf("NewAddr(%q).Port = %d, want %d", c.input, addr.Port, c.wantPort)
		}
	}
}

func TestAddrEncodeDecodeRoundTrip(t *testing.T) {
	addrs := []*Addr{
		{Type: AddrIPv4, Host: "1.2.3.4", Port: 1080},
		{Type: AddrIPv6, Host: "::1", Port: 1080},
		{Type: AddrDomain, Host: "example.com", Port: 443},
		{Type: AddrDomain, Host: "a", Port: 1},
	}
	for _, a := range addrs {
		buf := make([]byte, a.Length())
		n, err := a.Encode(buf)
		if err != nil {
			t.Errorf("Encode(%s) error: %v", a.String(), err)
			continue
		}
		if n != a.Length() {
			t.Errorf("Encode returned n=%d, Length=%d", n, a.Length())
		}
		var dec Addr
		dn, err := dec.Decode(buf)
		if err != nil {
			t.Errorf("Decode(%s) error: %v", a.String(), err)
			continue
		}
		if dn != n {
			t.Errorf("Decode consumed %d, expected %d", dn, n)
		}
		if dec.Type != a.Type {
			t.Errorf("Type mismatch: %#x vs %#x", dec.Type, a.Type)
		}
		if dec.Port != a.Port {
			t.Errorf("Port mismatch: %d vs %d", dec.Port, a.Port)
		}
		if dec.Host != a.Host {
			t.Errorf("Host mismatch: %q vs %q", dec.Host, a.Host)
		}
	}
}

func TestAddrEncodeDecodeEmptyHost(t *testing.T) {
	a := &Addr{Type: AddrIPv4, Host: "", Port: 0}
	buf := make([]byte, a.Length())
	if _, err := a.Encode(buf); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var dec Addr
	if _, err := dec.Decode(buf); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if dec.Host != "0.0.0.0" {
		t.Errorf("Host = %q, want 0.0.0.0", dec.Host)
	}
	if dec.Port != 0 {
		t.Errorf("Port = %d, want 0", dec.Port)
	}
}

func TestAddrEncodeInvalidHostFallback(t *testing.T) {
	// IPv4 with non-IP host falls back to 0.0.0.0
	a := &Addr{Type: AddrIPv4, Host: "not-an-ip", Port: 80}
	buf := make([]byte, a.Length())
	if _, err := a.Encode(buf); err != nil {
		t.Fatalf("Encode IPv4 invalid: %v", err)
	}
	var dec Addr
	if _, err := dec.Decode(buf); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if dec.Host != "0.0.0.0" {
		t.Errorf("Host = %q, want 0.0.0.0", dec.Host)
	}

	// IPv6 with non-IP host falls back to ::
	b := &Addr{Type: AddrIPv6, Host: "not-an-ip", Port: 80}
	buf2 := make([]byte, b.Length())
	if _, err := b.Encode(buf2); err != nil {
		t.Fatalf("Encode IPv6 invalid: %v", err)
	}
	var dec2 Addr
	if _, err := dec2.Decode(buf2); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if dec2.Host != "::" {
		t.Errorf("Host = %q, want ::", dec2.Host)
	}
}

func TestAddrEncodeOversizeDomain(t *testing.T) {
	a := &Addr{Type: AddrDomain, Host: strings.Repeat("x", 256), Port: 80}
	buf := make([]byte, a.Length())
	if _, err := a.Encode(buf); err != ErrBadFormat {
		t.Errorf("Encode oversize domain: got %v, want ErrBadFormat", err)
	}
}

func TestAddrDecodeErrors(t *testing.T) {
	// bad address type
	var a Addr
	if _, err := a.Decode([]byte{0x09, 0, 0, 0, 0, 0, 0}); err != ErrBadAddrType {
		t.Errorf("Decode bad type: got %v, want ErrBadAddrType", err)
	}
	// empty buffer
	var b Addr
	if _, err := b.Decode(nil); err != io.ErrUnexpectedEOF {
		t.Errorf("Decode nil: got %v, want io.ErrUnexpectedEOF", err)
	}
	// truncated IPv4 (needs 4+2 body bytes)
	var c Addr
	if _, err := c.Decode([]byte{AddrIPv4, 1, 2, 3}); err != io.ErrUnexpectedEOF {
		t.Errorf("Decode truncated IPv4: got %v, want io.ErrUnexpectedEOF", err)
	}
	// truncated IPv6
	var d Addr
	if _, err := d.Decode([]byte{AddrIPv6, 1, 2, 3}); err != io.ErrUnexpectedEOF {
		t.Errorf("Decode truncated IPv6: got %v, want io.ErrUnexpectedEOF", err)
	}
	// domain with missing length byte
	var e Addr
	if _, err := e.Decode([]byte{AddrDomain}); err != io.ErrUnexpectedEOF {
		t.Errorf("Decode domain no length: got %v, want io.ErrUnexpectedEOF", err)
	}
	// domain truncated body
	var f Addr
	if _, err := f.Decode([]byte{AddrDomain, 5, 'a', 'b', 'c'}); err != io.ErrUnexpectedEOF {
		t.Errorf("Decode truncated domain: got %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestAddrReadBody(t *testing.T) {
	// success: IPv4 body (no ATYP prefix)
	a := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 80}
	buf := make([]byte, a.Length())
	a.Encode(buf)
	var rd Addr
	rd.Type = AddrIPv4
	n, err := rd.readBody(bytes.NewReader(buf[1:]))
	if err != nil {
		t.Fatalf("readBody error: %v", err)
	}
	if rd.Host != "10.0.0.1" || rd.Port != 80 {
		t.Errorf("readBody got %s:%d", rd.Host, rd.Port)
	}
	if n != int64(len(buf)-1) {
		t.Errorf("readBody n=%d, want %d", n, len(buf)-1)
	}

	// bad type
	var bad Addr
	bad.Type = 0x09
	if _, err := bad.readBody(bytes.NewReader([]byte{0, 0, 0, 0, 0, 0})); err != ErrBadAddrType {
		t.Errorf("readBody bad type: got %v, want ErrBadAddrType", err)
	}

	// truncated IPv4
	var trunc Addr
	trunc.Type = AddrIPv4
	if _, err := trunc.readBody(bytes.NewReader([]byte{1, 2})); err == nil {
		t.Error("readBody truncated: expected error")
	}
}

func TestAddrCheckType(t *testing.T) {
	// already-set type is preserved
	a := &Addr{Type: AddrIPv6, Host: "1.2.3.4"}
	a.checkType()
	if a.Type != AddrIPv6 {
		t.Errorf("checkType changed set type: %#x", a.Type)
	}
	// unset + empty host -> IPv4
	b := &Addr{Type: 0, Host: ""}
	b.checkType()
	if b.Type != AddrIPv4 {
		t.Errorf("checkType empty host: %#x, want IPv4", b.Type)
	}
	// unset + domain
	c := &Addr{Type: 0, Host: "example.com"}
	c.checkType()
	if c.Type != AddrDomain {
		t.Errorf("checkType domain: %#x, want Domain", c.Type)
	}
	// unset + IPv4 string
	d := &Addr{Type: 0, Host: "1.2.3.4"}
	d.checkType()
	if d.Type != AddrIPv4 {
		t.Errorf("checkType ipv4: %#x, want IPv4", d.Type)
	}
	// unset + IPv6 string
	e := &Addr{Type: 0, Host: "::1"}
	e.checkType()
	if e.Type != AddrIPv6 {
		t.Errorf("checkType ipv6: %#x, want IPv6", e.Type)
	}
}

func TestAddrLength(t *testing.T) {
	cases := []struct {
		addr *Addr
		want int
	}{
		{&Addr{Type: AddrIPv4, Host: "1.2.3.4"}, 7},
		{&Addr{Type: AddrIPv6, Host: "::1"}, 19},
		{&Addr{Type: AddrDomain, Host: "abc"}, 7},
		{&Addr{Type: AddrDomain, Host: ""}, 4},
	}
	for _, c := range cases {
		if got := c.addr.Length(); got != c.want {
			t.Errorf("Length(%s) = %d, want %d", c.addr.String(), got, c.want)
		}
	}
}

func TestAddrString(t *testing.T) {
	a := &Addr{Type: AddrIPv4, Host: "1.2.3.4", Port: 1080}
	if got := a.String(); got != "1.2.3.4:1080" {
		t.Errorf("String = %q, want 1.2.3.4:1080", got)
	}
	b := &Addr{Type: AddrIPv6, Host: "::1", Port: 1080}
	if got := b.String(); got != "[::1]:1080" {
		t.Errorf("String = %q, want [::1]:1080", got)
	}
	var nilAddr *Addr
	if got := nilAddr.String(); got != "" {
		t.Errorf("nil String = %q, want empty", got)
	}
}
func TestAddrReadBodyDomainAndPortErrors(t *testing.T) {
	// domain: length byte read fails (empty reader)
	var a Addr
	a.Type = AddrDomain
	if _, err := a.readBody(bytes.NewReader(nil)); err == nil {
		t.Error("readBody domain length truncated: expected error")
	}
	// domain: name read fails (length=5 but only 2 bytes)
	var b Addr
	b.Type = AddrDomain
	if _, err := b.readBody(bytes.NewReader([]byte{5, 'a', 'b'})); err == nil {
		t.Error("readBody domain name truncated: expected error")
	}
	// IPv4: port read fails (4 IP bytes, no port)
	var c Addr
	c.Type = AddrIPv4
	if _, err := c.readBody(bytes.NewReader([]byte{1, 2, 3, 4})); err == nil {
		t.Error("readBody IPv4 port truncated: expected error")
	}
	// IPv6: port read fails (16 IP bytes, no port)
	var d Addr
	d.Type = AddrIPv6
	if _, err := d.readBody(bytes.NewReader(make([]byte, 16))); err == nil {
		t.Error("readBody IPv6 port truncated: expected error")
	}
	// domain success via readBody
	e := &Addr{Type: AddrDomain, Host: "host.com", Port: 999}
	buf := make([]byte, e.Length())
	e.Encode(buf)
	var rd Addr
	rd.Type = AddrDomain
	if _, err := rd.readBody(bytes.NewReader(buf[1:])); err != nil {
		t.Fatalf("readBody domain success: %v", err)
	}
	if rd.Host != "host.com" || rd.Port != 999 {
		t.Errorf("readBody domain got %s:%d", rd.Host, rd.Port)
	}
}
