package socks5

import (
	"bytes"
	"encoding/binary"
	"gocks/internal/constant"
	"net"
	"testing"
)

func TestParseUDPRequestIPv4(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, constant.AddrIPv4, 8, 8, 8, 8, 0x00, 0x35}
	data = append(data, []byte("DNS query")...)

	header, payload, err := parseUDPRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	if header.AddrType != constant.AddrIPv4 {
		t.Error("wrong addr type")
	}
	if !bytes.Equal(header.DstAddr, []byte{8, 8, 8, 8}) {
		t.Error("wrong addr")
	}
	if header.DstPort != 53 {
		t.Error("wrong port")
	}
	if string(payload) != "DNS query" {
		t.Error("wrong payload")
	}
}

func TestParseUDPRequestDomain(t *testing.T) {
	domain := "example.com"
	data := []byte{0x00, 0x00, 0x00, constant.AddrDomain, byte(len(domain))}
	data = append(data, []byte(domain)...)
	data = append(data, 0x00, 0x50)
	data = append(data, []byte("GET / HTTP/1.1")...)

	header, payload, err := parseUDPRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	if header.AddrType != constant.AddrDomain {
		t.Error("wrong addr type")
	}
	if string(header.DstAddr) != domain {
		t.Error("wrong domain")
	}
	if header.DstPort != 80 {
		t.Error("wrong port")
	}
	if string(payload) != "GET / HTTP/1.1" {
		t.Error("wrong payload")
	}
}

func TestParseUDPRequestFragment(t *testing.T) {
	data := []byte{0x00, 0x00, 0x01, constant.AddrIPv4, 8, 8, 8, 8, 0x00, 0x35}
	header, _, err := parseUDPRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	if header.Frag != 1 {
		t.Error("wrong frag")
	}
}

func TestResolveUDPTargetIPv4(t *testing.T) {
	header := &UDPHeader{AddrType: constant.AddrIPv4, DstAddr: []byte{8, 8, 8, 8}, DstPort: 53}
	addr, err := resolveUDPTarget(header)
	if err != nil {
		t.Fatal(err)
	}
	if addr.Port != 53 {
		t.Error("wrong port")
	}
	if !addr.IP.Equal(net.ParseIP("8.8.8.8")) {
		t.Error("wrong IP")
	}
}

func TestResolveUDPTargetDomain(t *testing.T) {
	header := &UDPHeader{AddrType: constant.AddrDomain, DstAddr: []byte("localhost"), DstPort: 53}
	addr, err := resolveUDPTarget(header)
	if err != nil {
		t.Fatal(err)
	}
	if addr.Port != 53 {
		t.Error("wrong port")
	}
	if !addr.IP.IsLoopback() {
		t.Error("expected loopback IP")
	}
}

func TestBuildUDPResponseIPv4(t *testing.T) {
	target := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 80}
	payload := []byte("response data")
	resp := buildUDPResponse(target, payload)

	if resp[0] != 0x00 || resp[1] != 0x00 || resp[2] != 0x00 {
		t.Error("wrong RSV")
	}
	if resp[3] != constant.AddrIPv4 {
		t.Error("wrong addr type")
	}
	port := binary.BigEndian.Uint16(resp[8:10])
	if port != 80 {
		t.Error("wrong port")
	}
	if string(resp[10:]) != "response data" {
		t.Error("wrong payload")
	}
}

func TestBuildUDPResponseIPv6(t *testing.T) {
	target := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 443}
	payload := []byte("v6resp")
	resp := buildUDPResponse(target, payload)

	if resp[3] != constant.AddrIPv6 {
		t.Error("wrong addr type")
	}
	port := binary.BigEndian.Uint16(resp[20:22])
	if port != 443 {
		t.Error("wrong port")
	}
	if string(resp[22:]) != "v6resp" {
		t.Error("wrong payload")
	}
}

func TestWriteUDPAssociateResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	addr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 9999}
	go writeUDPAssociateResponse(server, addr)

	buf := make([]byte, 32)
	n, _ := client.Read(buf)
	resp := buf[:n]

	if resp[0] != constant.Socks5Version {
		t.Error("wrong version")
	}
	if resp[1] != 0x00 {
		t.Error("wrong rep")
	}
	port := binary.BigEndian.Uint16(resp[8:10])
	if port != 9999 {
		t.Error("wrong port")
	}
}
