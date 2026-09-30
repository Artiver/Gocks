package socks5

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReplyRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		rep  byte
		addr *Addr
	}{
		{"success-ipv4", RepSucceeded, &Addr{Type: AddrIPv4, Host: "192.168.1.10", Port: 40000}},
		{"success-ipv6", RepSucceeded, &Addr{Type: AddrIPv6, Host: "2001:db8::2", Port: 1080}},
		{"refused-domain", RepConnRefused, &Addr{Type: AddrDomain, Host: "proxy.local", Port: 1080}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := NewReply(tc.rep, tc.addr).Write(&buf); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got, err := ReadReply(&buf)
			if err != nil {
				t.Fatalf("ReadReply: %v", err)
			}
			if got.Rep != tc.rep {
				t.Fatalf("got rep %d want %d", got.Rep, tc.rep)
			}
			if got.Addr.Host != tc.addr.Host || got.Addr.Port != tc.addr.Port {
				t.Fatalf("got %+v want %+v", got.Addr, tc.addr)
			}
		})
	}
}

func TestReplyWriteNilAddr(t *testing.T) {
	var buf bytes.Buffer
	if err := NewReply(RepConnRefused, nil).Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := []byte{Version, RepConnRefused, 0x00, AddrIPv4, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("got %v want %v", buf.Bytes(), want)
	}
}

func TestReplyExactFraming(t *testing.T) {
	var buf bytes.Buffer
	if err := NewReply(RepSucceeded, &Addr{Type: AddrIPv6, Host: "::1", Port: 1080}).Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	payload := []byte("tunnel-data")
	buf.Write(payload)

	r := bytes.NewReader(buf.Bytes())
	if _, err := ReadReply(r); err != nil {
		t.Fatalf("ReadReply: %v", err)
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(rest, payload) {
		t.Fatalf("payload lost: got %q want %q", rest, payload)
	}
}

func TestReadReplyBadVersion(t *testing.T) {
	wire := []byte{0x04, RepSucceeded, 0x00, AddrIPv4, 1, 2, 3, 4, 0, 80}
	if _, err := ReadReply(bytes.NewReader(wire)); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

func TestReadReplyBadAddrType(t *testing.T) {
	wire := []byte{Version, RepSucceeded, 0x00, 0x09}
	if _, err := ReadReply(bytes.NewReader(wire)); !errors.Is(err, ErrBadAddrType) {
		t.Fatalf("want ErrBadAddrType, got %v", err)
	}
}

func TestReprString(t *testing.T) {
	if got := ReprString(RepHostUnreachable); got != "host unreachable" {
		t.Fatalf("got %q", got)
	}
	if got := ReprString(0x7F); got != "unknown" {
		t.Fatalf("got %q", got)
	}
}
