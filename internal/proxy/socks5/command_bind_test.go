package socks5

import (
	"encoding/binary"
	"gocks/internal/constant"
	"net"
	"testing"
)

func TestWriteBindResponseIPv4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	go writeBindResponse(server, addr)

	buf := make([]byte, 32)
	n, _ := client.Read(buf)
	resp := buf[:n]

	if resp[0] != constant.Socks5Version {
		t.Error("wrong version")
	}
	if resp[1] != 0x00 {
		t.Error("wrong rep")
	}
	if resp[3] != constant.AddrIPv4 {
		t.Error("wrong addr type")
	}
	port := binary.BigEndian.Uint16(resp[8:10])
	if port != 12345 {
		t.Error("wrong port")
	}
}

func TestWriteBindResponseIPv6(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	addr := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 54321}
	go writeBindResponse(server, addr)

	buf := make([]byte, 32)
	n, _ := client.Read(buf)
	resp := buf[:n]

	if resp[3] != constant.AddrIPv6 {
		t.Error("wrong addr type")
	}
	port := binary.BigEndian.Uint16(resp[20:22])
	if port != 54321 {
		t.Error("wrong port")
	}
}
