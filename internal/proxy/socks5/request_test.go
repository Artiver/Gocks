package socks5

import (
	"bytes"
	"gocks/internal/constant"
	"net"
	"strings"
	"testing"
)

func TestReadRequestAddrIPv4(t *testing.T) {
	data := []byte{192, 168, 1, 1, 0x1f, 0x90}
	addr, err := readRequestAddr(bytes.NewReader(data), constant.AddrIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "192.168.1.1:8080" {
		t.Fatalf("unexpected address: %s", addr)
	}
}

func TestReadRequestAddrIPv6(t *testing.T) {
	ip := net.ParseIP("::1")
	data := ip.To16()
	data = append(data, 0x1f, 0x90)
	addr, err := readRequestAddr(bytes.NewReader(data), constant.AddrIPv6)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(addr, ":8080") {
		t.Fatalf("unexpected address: %s", addr)
	}
}

func TestReadRequestAddrDomain(t *testing.T) {
	domain := "example.com"
	data := []byte{byte(len(domain))}
	data = append(data, []byte(domain)...)
	data = append(data, 0x00, 0x50)
	addr, err := readRequestAddr(bytes.NewReader(data), constant.AddrDomain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "example.com:80" {
		t.Fatalf("unexpected address: %s", addr)
	}
}

func TestReadRequestAddrMaxDomain(t *testing.T) {
	domain := strings.Repeat("a", 255)
	data := []byte{255}
	data = append(data, []byte(domain)...)
	data = append(data, 0x1f, 0x90)
	addr, err := readRequestAddr(bytes.NewReader(data), constant.AddrDomain)
	if err != nil {
		t.Fatalf("unexpected error for max length domain: %v", err)
	}
	if !strings.HasPrefix(addr, strings.Repeat("a", 255)) {
		t.Fatalf("unexpected address: %s", addr)
	}
}

func TestReadRequestAddrUnsupportedType(t *testing.T) {
	_, err := readRequestAddr(bytes.NewReader([]byte{1, 2, 3}), 0x09)
	if err == nil {
		t.Fatal("expected error for unsupported address type")
	}
}

func TestReadRequestAddrEmptyDomain(t *testing.T) {
	data := []byte{0x00, 0x00, 0x50}
	_, err := readRequestAddr(bytes.NewReader(data), constant.AddrDomain)
	if err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestReadRequestAddrIPv4InsufficientData(t *testing.T) {
	data := []byte{192, 168, 1}
	_, err := readRequestAddr(bytes.NewReader(data), constant.AddrIPv4)
	if err == nil {
		t.Fatal("expected error for insufficient data")
	}
}

func TestReadRequestAddrDomainInsufficientData(t *testing.T) {
	data := []byte{10, 'a', 'b', 'c'}
	_, err := readRequestAddr(bytes.NewReader(data), constant.AddrDomain)
	if err == nil {
		t.Fatal("expected error for insufficient domain data")
	}
}
