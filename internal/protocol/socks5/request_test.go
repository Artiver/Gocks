package socks5

import (
	"bytes"
	"strings"
	"testing"
)

func TestRequestWriteReadRoundTrip(t *testing.T) {
	addrs := []*Addr{
		{Type: AddrIPv4, Host: "1.2.3.4", Port: 1080},
		{Type: AddrIPv6, Host: "::1", Port: 1080},
		{Type: AddrDomain, Host: "example.com", Port: 443},
	}
	for _, addr := range addrs {
		for _, cmd := range []byte{CmdConnect, CmdBind, CmdUDP} {
			req := NewRequest(cmd, addr)
			var buf bytes.Buffer
			if err := req.Write(&buf); err != nil {
				t.Fatalf("Write error: %v", err)
			}
			got, err := ReadRequest(&buf)
			if err != nil {
				t.Fatalf("ReadRequest error: %v", err)
			}
			if got.Cmd != cmd {
				t.Errorf("Cmd mismatch: %#x vs %#x", got.Cmd, cmd)
			}
			if got.Addr.Type != addr.Type {
				t.Errorf("Addr type mismatch: %#x vs %#x", got.Addr.Type, addr.Type)
			}
			if got.Addr.Port != addr.Port {
				t.Errorf("Addr port mismatch: %d vs %d", got.Addr.Port, addr.Port)
			}
			if got.Addr.Host != addr.Host {
				t.Errorf("Addr host mismatch: %q vs %q", got.Addr.Host, addr.Host)
			}
		}
	}
}

func TestRequestWriteNilAddr(t *testing.T) {
	req := NewRequest(CmdConnect, nil)
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatalf("Write nil addr error: %v", err)
	}
	got, err := ReadRequest(&buf)
	if err != nil {
		t.Fatalf("ReadRequest error: %v", err)
	}
	if got.Cmd != CmdConnect {
		t.Errorf("Cmd mismatch: %#x", got.Cmd)
	}
	if got.Addr.Type != AddrIPv4 {
		t.Errorf("Type mismatch: %#x, want IPv4", got.Addr.Type)
	}
	if got.Addr.Host != "0.0.0.0" {
		t.Errorf("Host mismatch: %q, want 0.0.0.0", got.Addr.Host)
	}
}

func TestReadRequestErrors(t *testing.T) {
	// bad version
	_, err := ReadRequest(bytes.NewReader([]byte{0x04, CmdConnect, 0x00, AddrIPv4, 1, 2, 3, 4, 0, 0}))
	if err != ErrBadVersion {
		t.Errorf("bad version: got %v, want ErrBadVersion", err)
	}
	// bad format (RSV != 0)
	_, err = ReadRequest(bytes.NewReader([]byte{Version, CmdConnect, 0x01, AddrIPv4, 1, 2, 3, 4, 0, 0}))
	if err != ErrBadFormat {
		t.Errorf("bad format: got %v, want ErrBadFormat", err)
	}
	// truncated header
	_, err = ReadRequest(bytes.NewReader([]byte{Version, CmdConnect}))
	if err == nil {
		t.Error("truncated header: expected error")
	}
	// truncated body
	_, err = ReadRequest(bytes.NewReader([]byte{Version, CmdConnect, 0x00, AddrIPv4, 1, 2}))
	if err == nil {
		t.Error("truncated body: expected error")
	}
}
func TestRequestWriteEncodeError(t *testing.T) {
	req := NewRequest(CmdConnect, &Addr{Type: AddrDomain, Host: strings.Repeat("x", 256), Port: 80})
	var buf bytes.Buffer
	if err := req.Write(&buf); err != ErrBadFormat {
		t.Errorf("Write encode error: got %v, want ErrBadFormat", err)
	}
}
