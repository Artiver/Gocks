package socks5

import (
	"bytes"
	"gocks/internal/config"
	"gocks/internal/tunnel"
	"io"
	"net"
	"testing"
)

func runHandshake(t *testing.T, clientData []byte, needAuth bool, user, pass string) (error, []byte) {
	client, server := net.Pipe()

	pc := tunnel.NewPrefixConn(clientData, server)

	var serverRespBuf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(&serverRespBuf, client)
	}()

	if needAuth {
		config.ProxyConfig.Socks5Auth = []byte{0x01, 0x00}
		config.ProxyConfig.Username = user
		config.ProxyConfig.Password = pass
	} else {
		config.ProxyConfig.Socks5Auth = nil
	}

	var c net.Conn = pc
	err := socks5Handshake(&c)
	server.Close()
	<-done
	return err, serverRespBuf.Bytes()
}

func buildAuthRequest(user, pass string) []byte {
	req := []byte{0x01, byte(len(user))}
	req = append(req, []byte(user)...)
	req = append(req, byte(len(pass)))
	req = append(req, []byte(pass)...)
	return req
}

func TestHandshakeNoAuthSuccess(t *testing.T) {
	clientData := []byte{0x05, 0x01, 0x00}
	err, resp := runHandshake(t, clientData, false, "", "")
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if !bytes.Equal(resp, []byte{0x05, 0x00}) {
		t.Fatalf("unexpected response: %v", resp)
	}
}

func TestHandshakeAuthSuccess(t *testing.T) {
	user, pass := "admin", "123456"
	clientData := append([]byte{0x05, 0x01, 0x02}, buildAuthRequest(user, pass)...)
	err, resp := runHandshake(t, clientData, true, user, pass)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if !bytes.Contains(resp, []byte{0x05, 0x02}) {
		t.Error("missing method selection response")
	}
	if !bytes.Contains(resp, []byte{0x01, 0x00}) {
		t.Error("missing auth success response")
	}
}

func TestHandshakeAuthWrongPassword(t *testing.T) {
	user, pass := "admin", "123456"
	clientData := append([]byte{0x05, 0x01, 0x02}, buildAuthRequest(user, "wrong")...)
	err, resp := runHandshake(t, clientData, true, user, pass)
	if err == nil {
		t.Fatal("expected auth failure error")
	}
	if !bytes.Contains(resp, []byte{0x01, 0x01}) {
		t.Error("missing auth failed response")
	}
}

func TestHandshakeServerRequiresAuthButClientOnlyNoAuth(t *testing.T) {
	clientData := []byte{0x05, 0x01, 0x00}
	err, resp := runHandshake(t, clientData, true, "admin", "123456")
	if err == nil {
		t.Fatal("expected method mismatch error")
	}
	if !bytes.Contains(resp, []byte{0x05, 0xFF}) {
		t.Error("missing method not acceptable response")
	}
}

func TestHandshakeServerNoAuthButClientOnlyAuth(t *testing.T) {
	clientData := []byte{0x05, 0x01, 0x02}
	err, resp := runHandshake(t, clientData, false, "", "")
	if err == nil {
		t.Fatal("expected method mismatch error")
	}
	if !bytes.Contains(resp, []byte{0x05, 0xFF}) {
		t.Error("missing method not acceptable response")
	}
}

func TestHandshakeMixPrefixWithAuth(t *testing.T) {
	user, pass := "admin", "123456"
	initialReq := []byte{0x05, 0x01, 0x02}
	clientData := append(initialReq, buildAuthRequest(user, pass)...)

	err, resp := runHandshake(t, clientData, true, user, pass)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if !bytes.Contains(resp, []byte{0x05, 0x02}) {
		t.Error("missing method selection response")
	}
	if !bytes.Contains(resp, []byte{0x01, 0x00}) {
		t.Error("missing auth success response")
	}
}

func TestHandshakeLongUsernameNoPanic(t *testing.T) {
	longUser := make([]byte, 255)
	for i := range longUser {
		longUser[i] = 97
	}
	clientData := []byte{0x05, 0x01, 0x02}
	authReq := []byte{0x01, 255}
	authReq = append(authReq, longUser...)
	authReq = append(authReq, 0x00)
	clientData = append(clientData, authReq...)

	err, _ := runHandshake(t, clientData, true, "admin", "123456")
	if err == nil {
		t.Fatal("expected auth failure for wrong credentials")
	}
}

func TestHandshakeUnsupportedVersion(t *testing.T) {
	clientData := []byte{0x04, 0x01, 0x00}
	err, _ := runHandshake(t, clientData, false, "", "")
	if err == nil {
		t.Fatal("expected version error")
	}
}

func TestHandshakeClientOffersBothMethods(t *testing.T) {
	user, pass := "admin", "123456"
	clientData := append([]byte{0x05, 0x02, 0x00, 0x02}, buildAuthRequest(user, pass)...)
	err, resp := runHandshake(t, clientData, true, user, pass)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if !bytes.Contains(resp, []byte{0x05, 0x02}) {
		t.Error("server should prefer username/password auth")
	}
}
