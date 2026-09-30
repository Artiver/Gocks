package forward

import (
	"bytes"
	"gocks/internal/config"
	"gocks/internal/constant"
	"io"
	"net"
	"testing"
)

func TestBuildCommandRequestIPv4(t *testing.T) {
	req := buildCommandRequest(constant.CmdConnect, "192.168.1.1")
	if req[0] != constant.Socks5Version {
		t.Error("wrong version")
	}
	if req[1] != constant.CmdConnect {
		t.Error("wrong cmd")
	}
	if req[3] != constant.AddrIPv4 {
		t.Error("wrong addr type")
	}
	if !bytes.Equal(req[4:8], []byte{192, 168, 1, 1}) {
		t.Error("wrong IP")
	}
	if len(req) != 8 {
		t.Error("wrong length")
	}
}

func TestBuildCommandRequestIPv6(t *testing.T) {
	req := buildCommandRequest(constant.CmdConnect, "::1")
	if req[3] != constant.AddrIPv6 {
		t.Error("wrong addr type")
	}
	if len(req) != 20 {
		t.Error("wrong length")
	}
}

func TestBuildCommandRequestDomain(t *testing.T) {
	req := buildCommandRequest(constant.CmdUDP, "example.com")
	if req[1] != constant.CmdUDP {
		t.Error("wrong cmd")
	}
	if req[3] != constant.AddrDomain {
		t.Error("wrong addr type")
	}
	if req[4] != 11 {
		t.Error("wrong domain length")
	}
	if string(req[5:16]) != "example.com" {
		t.Error("wrong domain")
	}
}

func TestReadSocks5ResponseIPv4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	resp := []byte{constant.Socks5Version, 0x00, 0x00, constant.AddrIPv4, 127, 0, 0, 1, 0x1f, 0x90}
	go client.Write(resp)

	err := readSocks5Response(server)
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadSocks5ResponseDomain(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	domain := "example.com"
	resp := []byte{constant.Socks5Version, 0x00, 0x00, constant.AddrDomain, byte(len(domain))}
	resp = append(resp, []byte(domain)...)
	resp = append(resp, 0x00, 0x50)
	go client.Write(resp)

	err := readSocks5Response(server)
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadSocks5ResponseFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	resp := []byte{constant.Socks5Version, 0x05, 0x00, constant.AddrIPv4, 0, 0, 0, 0, 0, 0}
	go client.Write(resp)

	err := readSocks5Response(server)
	if err == nil {
		t.Fatal("expected error for failure response")
	}
}

func TestReadSocks5ResponseWrongVersion(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	resp := []byte{0x04, 0x00, 0x00, constant.AddrIPv4, 0, 0, 0, 0, 0, 0}
	go client.Write(resp)

	err := readSocks5Response(server)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestSocks5HandshakeNoAuth(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	config.ForwardConfig.Socks5Auth = nil

	go func() {
		buf := make([]byte, 4)
		_, _ = io.ReadFull(client, buf)
		_, _ = client.Write([]byte{constant.Socks5Version, 0x00})
	}()

	err := socks5Handshake(server)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSocks5HandshakeWithAuth(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	user, pass := "admin", "123456"
	config.ForwardConfig.Socks5Auth = []byte{0x01, byte(len(user))}
	config.ForwardConfig.Socks5Auth = append(config.ForwardConfig.Socks5Auth, []byte(user)...)
	config.ForwardConfig.Socks5Auth = append(config.ForwardConfig.Socks5Auth, byte(len(pass)))
	config.ForwardConfig.Socks5Auth = append(config.ForwardConfig.Socks5Auth, []byte(pass)...)

	go func() {
		buf := make([]byte, 4)
		_, _ = io.ReadFull(client, buf)
		_, _ = client.Write([]byte{constant.Socks5Version, 0x02})
		authBuf := make([]byte, 2+len(user)+1+len(pass))
		_, _ = io.ReadFull(client, authBuf)
		_, _ = client.Write([]byte{0x01, 0x00})
	}()

	err := socks5Handshake(server)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSocks5HandshakeAuthFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	config.ForwardConfig.Socks5Auth = []byte{0x01, 0x05, 'a', 'd', 'm', 'i', 'n', 0x06, '1', '2', '3', '4', '5', '6'}

	go func() {
		buf := make([]byte, 4)
		_, _ = io.ReadFull(client, buf)
		_, _ = client.Write([]byte{constant.Socks5Version, 0x02})
		authBuf := make([]byte, 14)
		_, _ = io.ReadFull(client, authBuf)
		_, _ = client.Write([]byte{0x01, 0x01})
	}()

	err := socks5Handshake(server)
	if err == nil {
		t.Fatal("expected auth failure error")
	}
}
