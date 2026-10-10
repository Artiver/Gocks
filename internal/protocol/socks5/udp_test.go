package socks5

import (
	"bytes"
	"strings"
	"testing"
)

func TestUDPDatagramMarshalUnmarshalRoundTrip(t *testing.T) {
	cases := []struct {
		header *UDPHeader
		data   []byte
	}{
		{NewUDPHeader(0, 0, &Addr{Type: AddrIPv4, Host: "1.2.3.4", Port: 1080}), []byte("hello")},
		{NewUDPHeader(0, 1, &Addr{Type: AddrIPv6, Host: "::1", Port: 1080}), []byte{}},
		{NewUDPHeader(0x1234, 2, &Addr{Type: AddrDomain, Host: "example.com", Port: 443}), []byte("data payload")},
		{NewUDPHeader(0, 0, &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 80}), nil},
	}
	for _, c := range cases {
		dg := NewUDPDatagram(c.header, c.data)
		buf, err := dg.Marshal()
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var got UDPDatagram
		if err := got.Unmarshal(buf); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if got.Header.Rsv != c.header.Rsv {
			t.Errorf("Rsv mismatch: %#x vs %#x", got.Header.Rsv, c.header.Rsv)
		}
		if got.Header.Frag != c.header.Frag {
			t.Errorf("Frag mismatch: %#x vs %#x", got.Header.Frag, c.header.Frag)
		}
		if got.Header.Addr.Type != c.header.Addr.Type {
			t.Errorf("Addr type mismatch: %#x vs %#x", got.Header.Addr.Type, c.header.Addr.Type)
		}
		if got.Header.Addr.Port != c.header.Addr.Port {
			t.Errorf("Port mismatch: %d vs %d", got.Header.Addr.Port, c.header.Addr.Port)
		}
		if got.Header.Addr.Host != c.header.Addr.Host {
			t.Errorf("Host mismatch: %q vs %q", got.Header.Addr.Host, c.header.Addr.Host)
		}
		if !bytes.Equal(got.Data, c.data) {
			t.Errorf("Data mismatch: %q vs %q", got.Data, c.data)
		}
	}
}

func TestUDPHeaderMarshalNilAddr(t *testing.T) {
	h := NewUDPHeader(0, 0, nil)
	buf, err := h.Marshal()
	if err != nil {
		t.Fatalf("Marshal nil addr error: %v", err)
	}
	var got UDPHeader
	if _, err := got.Unmarshal(buf); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if got.Addr.Type != AddrIPv4 {
		t.Errorf("Type mismatch: %#x, want IPv4", got.Addr.Type)
	}
}

func TestUDPHeaderUnmarshalErrors(t *testing.T) {
	// too short
	var h UDPHeader
	if _, err := h.Unmarshal([]byte{0, 0}); err == nil {
		t.Error("too short: expected error")
	}
	// bad addr type
	var h2 UDPHeader
	if _, err := h2.Unmarshal([]byte{0, 0, 0, 0x09, 1, 2, 3, 4, 0, 0}); err == nil {
		t.Error("bad addr type: expected error")
	}
}

func TestUDPDatagramMarshalNilHeader(t *testing.T) {
	dg := &UDPDatagram{Data: []byte("test")}
	buf, err := dg.Marshal()
	if err != nil {
		t.Fatalf("Marshal nil header error: %v", err)
	}
	var got UDPDatagram
	if err := got.Unmarshal(buf); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if !bytes.Equal(got.Data, []byte("test")) {
		t.Errorf("Data mismatch: %q", got.Data)
	}
}

func TestUDPDatagramUnmarshalNilHeader(t *testing.T) {
	dg := NewUDPDatagram(NewUDPHeader(0, 0, &Addr{Type: AddrIPv4, Host: "1.2.3.4", Port: 80}), []byte("payload"))
	buf, err := dg.Marshal()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var got UDPDatagram
	if err := got.Unmarshal(buf); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if got.Header == nil {
		t.Fatal("Header should be allocated by Unmarshal")
	}
}
func TestUDPHeaderMarshalEncodeError(t *testing.T) {
	h := NewUDPHeader(0, 0, &Addr{Type: AddrDomain, Host: strings.Repeat("x", 256), Port: 80})
	if _, err := h.Marshal(); err != ErrBadFormat {
		t.Errorf("Marshal encode error: got %v, want ErrBadFormat", err)
	}
}

func TestUDPDatagramMarshalEncodeError(t *testing.T) {
	dg := NewUDPDatagram(NewUDPHeader(0, 0, &Addr{Type: AddrDomain, Host: strings.Repeat("x", 256), Port: 80}), nil)
	if _, err := dg.Marshal(); err != ErrBadFormat {
		t.Errorf("Marshal encode error: got %v, want ErrBadFormat", err)
	}
}

func TestUDPDatagramUnmarshalError(t *testing.T) {
	var dg UDPDatagram
	if err := dg.Unmarshal([]byte{0, 0}); err == nil {
		t.Error("expected error for too-short datagram")
	}
}
