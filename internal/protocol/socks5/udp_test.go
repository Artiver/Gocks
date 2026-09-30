package socks5

import (
	"errors"
	"io"
	"testing"
)

func TestUDPDatagramMarshalUnmarshal(t *testing.T) {
	cases := []struct {
		name string
		addr *Addr
	}{
		{"ipv4", &Addr{Type: AddrIPv4, Host: "8.8.8.8", Port: 53}},
		{"ipv6", &Addr{Type: AddrIPv6, Host: "2001:4860:4860::8888", Port: 53}},
		{"domain", &Addr{Type: AddrDomain, Host: "dns.example", Port: 53}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewUDPDatagram(NewUDPHeader(0, 0, tc.addr), []byte("dnsquery"))
			wire, err := d.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			var got UDPDatagram
			if err := got.Unmarshal(wire); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got.Header.Frag != 0 {
				t.Fatalf("got frag %d", got.Header.Frag)
			}
			if got.Header.Addr.Host != tc.addr.Host || got.Header.Addr.Port != tc.addr.Port {
				t.Fatalf("got %+v want %+v", got.Header.Addr, tc.addr)
			}
			if string(got.Data) != "dnsquery" {
				t.Fatalf("got payload %q", got.Data)
			}
		})
	}
}

func TestUDPDatagramUnmarshalAliasesPayload(t *testing.T) {
	d := NewUDPDatagram(NewUDPHeader(0, 0, &Addr{Type: AddrIPv4, Host: "1.1.1.1", Port: 53}), []byte("payload"))
	wire, err := d.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got UDPDatagram
	if err := got.Unmarshal(wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// The payload should be a sub-slice of the input, not a copy.
	got.Data[0] = 'P'
	if wire[len(wire)-len("payload")] != 'P' {
		t.Fatal("expected payload to alias the input buffer")
	}
}

func TestUDPDatagramFrag(t *testing.T) {
	d := NewUDPDatagram(NewUDPHeader(0, 3, &Addr{Type: AddrIPv4, Host: "1.2.3.4", Port: 9}), []byte("x"))
	wire, err := d.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got UDPDatagram
	if err := got.Unmarshal(wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Header.Frag != 3 {
		t.Fatalf("got frag %d want 3", got.Header.Frag)
	}
}

func TestUDPHeaderUnmarshalShort(t *testing.T) {
	if _, err := new(UDPHeader).Unmarshal([]byte{0x00, 0x00}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want ErrUnexpectedEOF, got %v", err)
	}
}
