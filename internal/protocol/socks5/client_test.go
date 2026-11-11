package socks5

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

func pipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

func TestClientHandshakeNoAuth(t *testing.T) {
	client, server := pipePair(t)

	methodsCh := make(chan []byte, 1)
	go func() {
		methods, err := ReadMethods(server)
		if err != nil {
			server.Close()
			return
		}
		methodsCh <- methods
		WriteMethod(MethodNoAuth, server)
	}()

	if err := ClientHandshake(client, nil); err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	methods := <-methodsCh
	if !HasMethod(methods, MethodNoAuth) {
		t.Error("client did not offer no-auth")
	}
	if HasMethod(methods, MethodUserPass) {
		t.Error("client offered user/pass without credentials")
	}
}

func TestClientHandshakeUserPassSuccess(t *testing.T) {
	client, server := pipePair(t)

	reqCh := make(chan *UserPassRequest, 1)
	go func() {
		if _, err := ReadMethods(server); err != nil {
			server.Close()
			return
		}
		WriteMethod(MethodUserPass, server)
		req, err := ReadUserPassRequest(server)
		if err != nil {
			server.Close()
			return
		}
		reqCh <- req
		NewUserPassResponse(UserPassVersion, UserPassSuccess).Write(server)
	}()

	cred := &Credential{Username: "user", Password: "pass"}
	if err := ClientHandshake(client, cred); err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	req := <-reqCh
	if req.Username != cred.Username || req.Password != cred.Password {
		t.Errorf("credentials = %q/%q, want %q/%q", req.Username, req.Password, cred.Username, cred.Password)
	}
}

func TestClientHandshakeUserPassFailure(t *testing.T) {
	client, server := pipePair(t)

	go func() {
		if _, err := ReadMethods(server); err != nil {
			server.Close()
			return
		}
		WriteMethod(MethodUserPass, server)
		if _, err := ReadUserPassRequest(server); err != nil {
			server.Close()
			return
		}
		NewUserPassResponse(UserPassVersion, UserPassFailure).Write(server)
	}()

	err := ClientHandshake(client, &Credential{Username: "user", Password: "pass"})
	if !errors.Is(err, ErrAuthFailure) {
		t.Fatalf("error = %v, want ErrAuthFailure", err)
	}
}

func TestClientHandshakeRequiresCredentials(t *testing.T) {
	client, server := pipePair(t)

	go func() {
		if _, err := ReadMethods(server); err != nil {
			return
		}
		WriteMethod(MethodUserPass, server)
	}()

	err := ClientHandshake(client, nil)
	if err == nil || !strings.Contains(err.Error(), "requires authentication") {
		t.Fatalf("error = %v, want missing-credentials error", err)
	}
}

func TestClientHandshakeNoAcceptableMethod(t *testing.T) {
	client, server := pipePair(t)

	go func() {
		if _, err := ReadMethods(server); err != nil {
			return
		}
		WriteMethod(MethodNoAcceptable, server)
	}()

	if err := ClientHandshake(client, nil); !errors.Is(err, ErrBadMethod) {
		t.Fatalf("error = %v, want ErrBadMethod", err)
	}
}

func TestClientHandshakeBadVersion(t *testing.T) {
	client, server := pipePair(t)

	go func() {
		if _, err := ReadMethods(server); err != nil {
			return
		}
		server.Write([]byte{0x04, 0x00})
	}()

	if err := ClientHandshake(client, nil); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("error = %v, want ErrBadVersion", err)
	}
}

func TestClientHandshakeUnknownMethod(t *testing.T) {
	client, server := pipePair(t)

	go func() {
		if _, err := ReadMethods(server); err != nil {
			return
		}
		WriteMethod(0x80, server)
	}()

	err := ClientHandshake(client, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported method") {
		t.Fatalf("error = %v, want unsupported method", err)
	}
}

func TestClientHandshakeWriteGreetingError(t *testing.T) {
	client, server := net.Pipe()
	server.Close()
	defer client.Close()

	if err := ClientHandshake(client, nil); err == nil {
		t.Fatal("ClientHandshake = nil error, want write failure")
	}
}

func TestClientHandshakeReadMethodError(t *testing.T) {
	client, server := pipePair(t)

	go func() {
		if _, err := ReadMethods(server); err != nil {
			return
		}
		server.Close()
	}()

	if err := ClientHandshake(client, nil); err == nil {
		t.Fatal("ClientHandshake = nil error, want read failure")
	}
}

func TestClientHandshakeWriteCredentialsError(t *testing.T) {
	client, server := pipePair(t)

	go func() {
		if _, err := ReadMethods(server); err != nil {
			return
		}
		WriteMethod(MethodUserPass, server)
		server.Close()
	}()

	if err := ClientHandshake(client, &Credential{Username: "u", Password: "p"}); err == nil {
		t.Fatal("ClientHandshake = nil error, want write failure")
	}
}

func TestClientHandshakeReadCredentialsResponseError(t *testing.T) {
	client, server := pipePair(t)

	go func() {
		if _, err := ReadMethods(server); err != nil {
			return
		}
		WriteMethod(MethodUserPass, server)
		if _, err := ReadUserPassRequest(server); err != nil {
			return
		}
		server.Close()
	}()

	if err := ClientHandshake(client, &Credential{Username: "u", Password: "p"}); !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v, want EOF", err)
	}
}
