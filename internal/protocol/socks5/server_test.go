package socks5

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type handshakeResult struct {
	id  string
	err error
}

// runServerHandshake starts ServerHandshake on one end of a net.Pipe, runs the
// client script synchronously on the other end, then returns the handshake
// outcome.
func runServerHandshake(t *testing.T, selector Selector, script func(net.Conn)) handshakeResult {
	t.Helper()

	server, client := net.Pipe()
	defer client.Close()

	ch := make(chan handshakeResult, 1)
	go func() {
		id, err := ServerHandshake(server, selector)
		server.Close()
		ch <- handshakeResult{id, err}
	}()

	script(client)

	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("ServerHandshake timed out")
		return handshakeResult{}
	}
}

func readMethod(t *testing.T, c net.Conn) byte {
	t.Helper()
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if reply[0] != Version {
		t.Fatalf("unexpected version in method reply: %d", reply[0])
	}
	return reply[1]
}

func TestServerHandshakeNoAuth(t *testing.T) {
	selector := NewServerSelector()

	var method byte
	res := runServerHandshake(t, selector, func(c net.Conn) {
		c.Write([]byte{Version, 2, MethodNoAuth, MethodUserPass})
		method = readMethod(t, c)
	})

	if res.err != nil {
		t.Fatalf("handshake error: %v", res.err)
	}
	if res.id != "" {
		t.Fatalf("expected empty client ID, got %q", res.id)
	}
	if method != MethodNoAuth {
		t.Fatalf("expected MethodNoAuth, got %d", method)
	}
}

func TestServerHandshakeUserPassSuccess(t *testing.T) {
	selector := NewServerSelector(Credential{Username: "alice", Password: "s3cret"})

	var method byte
	var status byte
	res := runServerHandshake(t, selector, func(c net.Conn) {
		c.Write([]byte{Version, 2, MethodNoAuth, MethodUserPass})
		method = readMethod(t, c)

		if err := NewUserPassRequest(UserPassVersion, "alice", "s3cret").Write(c); err != nil {
			return
		}
		var resp [2]byte
		if _, err := io.ReadFull(c, resp[:]); err == nil {
			status = resp[1]
		}
	})

	if res.err != nil {
		t.Fatalf("handshake error: %v", res.err)
	}
	if res.id != "alice" {
		t.Fatalf("expected client ID alice, got %q", res.id)
	}
	if method != MethodUserPass {
		t.Fatalf("expected MethodUserPass, got %d", method)
	}
	if status != UserPassSuccess {
		t.Fatalf("expected success status, got %d", status)
	}
}

func TestServerHandshakeUserPassFailure(t *testing.T) {
	selector := NewServerSelector(Credential{Username: "alice", Password: "s3cret"})

	var status byte
	res := runServerHandshake(t, selector, func(c net.Conn) {
		c.Write([]byte{Version, 1, MethodUserPass})
		readMethod(t, c)

		if err := NewUserPassRequest(UserPassVersion, "alice", "wrong").Write(c); err != nil {
			return
		}
		var resp [2]byte
		if _, err := io.ReadFull(c, resp[:]); err == nil {
			status = resp[1]
		}
	})

	if !errors.Is(res.err, ErrAuthFailure) {
		t.Fatalf("want ErrAuthFailure, got %v", res.err)
	}
	if status != UserPassFailure {
		t.Fatalf("expected failure status, got %d", status)
	}
}

func TestServerHandshakeNoAcceptable(t *testing.T) {
	// Auth required, but the client only offers no-auth.
	selector := NewServerSelector(Credential{Username: "alice", Password: "s3cret"})

	var method byte
	res := runServerHandshake(t, selector, func(c net.Conn) {
		c.Write([]byte{Version, 1, MethodNoAuth})
		method = readMethod(t, c)
	})

	if !errors.Is(res.err, ErrBadMethod) {
		t.Fatalf("want ErrBadMethod, got %v", res.err)
	}
	if method != MethodNoAcceptable {
		t.Fatalf("expected MethodNoAcceptable, got %d", method)
	}
}

func TestServerHandshakeNoAuthRejectsUserPassOnlyClient(t *testing.T) {
	// No auth configured, but the client only offers user/pass.
	selector := NewServerSelector()

	var method byte
	res := runServerHandshake(t, selector, func(c net.Conn) {
		c.Write([]byte{Version, 1, MethodUserPass})
		method = readMethod(t, c)
	})

	if !errors.Is(res.err, ErrBadMethod) {
		t.Fatalf("want ErrBadMethod, got %v", res.err)
	}
	if method != MethodNoAcceptable {
		t.Fatalf("expected MethodNoAcceptable, got %d", method)
	}
}

func TestServerSelectorSelect(t *testing.T) {
	auth := NewServerSelector(Credential{Username: "u", Password: "p"})
	open := NewServerSelector()

	cases := []struct {
		name     string
		selector *ServerSelector
		methods  []byte
		want     byte
	}{
		{"noauth-offers-noauth", open, []byte{MethodNoAuth}, MethodNoAuth},
		{"noauth-offers-userpass", open, []byte{MethodUserPass}, MethodNoAcceptable},
		{"noauth-empty", open, nil, MethodNoAcceptable},
		{"auth-offers-userpass", auth, []byte{MethodNoAuth, MethodUserPass}, MethodUserPass},
		{"auth-offers-noauth", auth, []byte{MethodNoAuth}, MethodNoAcceptable},
		{"auth-empty", auth, nil, MethodNoAcceptable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.selector.Select(tc.methods); got != tc.want {
				t.Fatalf("Select=%d want %d", got, tc.want)
			}
		})
	}
}
