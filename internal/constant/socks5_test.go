package constant

import (
	"bytes"
	"sync"
	"testing"
)

func TestNewClientRequestIPv4ReturnsIndependentSlice(t *testing.T) {
	a := NewClientRequestIPv4()
	b := NewClientRequestIPv4()
	a[0] = 0xFF
	if b[0] == 0xFF {
		t.Fatal("slices share backing array")
	}
}

func TestNewClientRequestIPv6ReturnsIndependentSlice(t *testing.T) {
	a := NewClientRequestIPv6()
	b := NewClientRequestIPv6()
	a[0] = 0xFF
	if b[0] == 0xFF {
		t.Fatal("slices share backing array")
	}
}

func TestNewClientRequestDomainReturnsIndependentSlice(t *testing.T) {
	a := NewClientRequestDomain()
	b := NewClientRequestDomain()
	a[0] = 0xFF
	if b[0] == 0xFF {
		t.Fatal("slices share backing array")
	}
}

func TestNewClientRequestValues(t *testing.T) {
	if !bytes.Equal(NewClientRequestIPv4(), []byte{Socks5Version, CmdConnect, 0x00, AddrIPv4}) {
		t.Fatal("unexpected IPv4 request bytes")
	}
	if !bytes.Equal(NewClientRequestIPv6(), []byte{Socks5Version, CmdConnect, 0x00, AddrIPv6}) {
		t.Fatal("unexpected IPv6 request bytes")
	}
	if !bytes.Equal(NewClientRequestDomain(), []byte{Socks5Version, CmdConnect, 0x00, AddrDomain}) {
		t.Fatal("unexpected Domain request bytes")
	}
}

func TestNewClientRequestConcurrentAppend(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			req := NewClientRequestIPv4()
			req = append(req, 1, 2, 3, 4)
			if !bytes.Equal(req[:4], []byte{Socks5Version, CmdConnect, 0x00, AddrIPv4}) {
				t.Error("IPv4 prefix corrupted")
			}
		}()
		go func() {
			defer wg.Done()
			req := NewClientRequestIPv6()
			req = append(req, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
			if !bytes.Equal(req[:4], []byte{Socks5Version, CmdConnect, 0x00, AddrIPv6}) {
				t.Error("IPv6 prefix corrupted")
			}
		}()
		go func() {
			defer wg.Done()
			req := NewClientRequestDomain()
			req = append(req, 11)
			req = append(req, []byte("example.com")...)
			if !bytes.Equal(req[:4], []byte{Socks5Version, CmdConnect, 0x00, AddrDomain}) {
				t.Error("Domain prefix corrupted")
			}
		}()
	}
	wg.Wait()
}
