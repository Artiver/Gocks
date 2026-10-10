package socks5

import (
	"bytes"
	"strings"
	"testing"
)

func TestReplyWriteReadRoundTrip(t *testing.T) {
	addrs := []*Addr{
		{Type: AddrIPv4, Host: "1.2.3.4", Port: 1080},
		{Type: AddrIPv6, Host: "::1", Port: 1080},
		{Type: AddrDomain, Host: "example.com", Port: 443},
	}
	reps := []byte{RepSucceeded, RepConnRefused, RepHostUnreachable, RepFailure}
	for _, addr := range addrs {
		for _, rep := range reps {
			r := NewReply(rep, addr)
			var buf bytes.Buffer
			if err := r.Write(&buf); err != nil {
				t.Fatalf("Write error: %v", err)
			}
			got, err := ReadReply(&buf)
			if err != nil {
				t.Fatalf("ReadReply error: %v", err)
			}
			if got.Rep != rep {
				t.Errorf("Rep mismatch: %#x vs %#x", got.Rep, rep)
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

func TestReplyWriteNilAddr(t *testing.T) {
	r := NewReply(RepSucceeded, nil)
	var buf bytes.Buffer
	if err := r.Write(&buf); err != nil {
		t.Fatalf("Write nil addr error: %v", err)
	}
	got, err := ReadReply(&buf)
	if err != nil {
		t.Fatalf("ReadReply error: %v", err)
	}
	if got.Rep != RepSucceeded {
		t.Errorf("Rep mismatch: %#x", got.Rep)
	}
	if got.Addr.Type != AddrIPv4 {
		t.Errorf("Type mismatch: %#x, want IPv4", got.Addr.Type)
	}
}

func TestReadReplyErrors(t *testing.T) {
	// bad version
	_, err := ReadReply(bytes.NewReader([]byte{0x04, RepSucceeded, 0x00, AddrIPv4, 1, 2, 3, 4, 0, 0}))
	if err != ErrBadVersion {
		t.Errorf("bad version: got %v, want ErrBadVersion", err)
	}
	// truncated header
	_, err = ReadReply(bytes.NewReader([]byte{Version}))
	if err == nil {
		t.Error("truncated header: expected error")
	}
	// truncated body
	_, err = ReadReply(bytes.NewReader([]byte{Version, RepSucceeded, 0x00, AddrIPv6, 1, 2, 3}))
	if err == nil {
		t.Error("truncated body: expected error")
	}
}
func TestReplyWriteEncodeError(t *testing.T) {
	r := NewReply(RepSucceeded, &Addr{Type: AddrDomain, Host: strings.Repeat("x", 256), Port: 80})
	var buf bytes.Buffer
	if err := r.Write(&buf); err != ErrBadFormat {
		t.Errorf("Write encode error: got %v, want ErrBadFormat", err)
	}
}
