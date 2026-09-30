package socks5

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
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
			var buf bytes.Buffer
			if err := NewRequest(CmdConnect, tc.addr).Write(&buf); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got, err := ReadRequest(&buf)
			if err != nil {
				t.Fatalf("ReadRequest: %v", err)
			}
			if got.Cmd != CmdConnect {
				t.Fatalf("got cmd %d want %d", got.Cmd, CmdConnect)
			}
			if got.Addr.Host != tc.addr.Host || got.Addr.Port != tc.addr.Port {
				t.Fatalf("got %+v want %+v", got.Addr, tc.addr)
			}
		})
	}
}

func TestRequestExactFraming(t *testing.T) {
	var buf bytes.Buffer
	req := NewRequest(CmdConnect, &Addr{Type: AddrDomain, Host: "example.com", Port: 443})
	if err := req.Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	payload := []byte("hello-target")
	buf.Write(payload)

	r := bytes.NewReader(buf.Bytes())
	if _, err := ReadRequest(r); err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(rest, payload) {
		t.Fatalf("pipelined payload lost: got %q want %q", rest, payload)
	}
}

func TestRequestFragmented(t *testing.T) {
	var buf bytes.Buffer
	if err := NewRequest(CmdConnect, &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 8443}).Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := ReadRequest(&oneByteReader{data: buf.Bytes()})
	if err != nil {
		t.Fatalf("ReadRequest fragmented: %v", err)
	}
	if got.Addr.Host != "10.0.0.1" || got.Addr.Port != 8443 {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestReadRequestBadVersion(t *testing.T) {
	wire := []byte{0x04, CmdConnect, 0x00, AddrIPv4, 1, 2, 3, 4, 0, 80}
	if _, err := ReadRequest(bytes.NewReader(wire)); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

func TestReadRequestBadRSV(t *testing.T) {
	wire := []byte{Version, CmdConnect, 0x01, AddrIPv4, 1, 2, 3, 4, 0, 80}
	if _, err := ReadRequest(bytes.NewReader(wire)); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("want ErrBadFormat, got %v", err)
	}
}

func TestReadRequestBadAddrType(t *testing.T) {
	wire := []byte{Version, CmdConnect, 0x00, 0x09}
	if _, err := ReadRequest(bytes.NewReader(wire)); !errors.Is(err, ErrBadAddrType) {
		t.Fatalf("want ErrBadAddrType, got %v", err)
	}
}

func TestRequestWriteNilAddr(t *testing.T) {
	var buf bytes.Buffer
	if err := NewRequest(CmdConnect, nil).Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := []byte{Version, CmdConnect, 0x00, AddrIPv4, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("got %v want %v", buf.Bytes(), want)
	}
}
