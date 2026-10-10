package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

func TestNewServerSelector(t *testing.T) {
	s := NewServerSelector()
	if s == nil {
		t.Fatal("NewServerSelector returned nil")
	}
	s2 := NewServerSelector(Credential{Username: "u", Password: "p"})
	if s2 == nil {
		t.Fatal("NewServerSelector with creds returned nil")
	}
}

func TestServerSelectorSelectNoCreds(t *testing.T) {
	s := NewServerSelector()
	if got := s.Select([]byte{MethodNoAuth, MethodUserPass}); got != MethodNoAuth {
		t.Errorf("Select with NoAuth available: got %#x, want NoAuth", got)
	}
	if got := s.Select([]byte{MethodUserPass}); got != MethodNoAcceptable {
		t.Errorf("Select without NoAuth: got %#x, want NoAcceptable", got)
	}
}

func TestServerSelectorSelectWithCreds(t *testing.T) {
	s := NewServerSelector(Credential{Username: "u", Password: "p"})
	if got := s.Select([]byte{MethodNoAuth, MethodUserPass}); got != MethodUserPass {
		t.Errorf("Select with UserPass available: got %#x, want UserPass", got)
	}
	if got := s.Select([]byte{MethodNoAuth}); got != MethodNoAcceptable {
		t.Errorf("Select without UserPass: got %#x, want NoAcceptable", got)
	}
}

func TestServerSelectorOnSelectedNoAuth(t *testing.T) {
	s := NewServerSelector()
	id, err := s.OnSelected(MethodNoAuth, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("OnSelected NoAuth error: %v", err)
	}
	if id != "" {
		t.Errorf("id = %q, want empty", id)
	}
}

func TestServerSelectorOnSelectedBadMethod(t *testing.T) {
	s := NewServerSelector()
	_, err := s.OnSelected(MethodGSSAPI, &bytes.Buffer{})
	if err != ErrBadMethod {
		t.Errorf("bad method: got %v, want ErrBadMethod", err)
	}
}

func TestServerSelectorOnSelectedUserPassSuccess(t *testing.T) {
	s := NewServerSelector(Credential{Username: "user", Password: "pass"})
	var buf bytes.Buffer
	if err := NewUserPassRequest(UserPassVersion, "user", "pass").Write(&buf); err != nil {
		t.Fatal(err)
	}
	id, err := s.OnSelected(MethodUserPass, &buf)
	if err != nil {
		t.Fatalf("OnSelected success error: %v", err)
	}
	if id != "user" {
		t.Errorf("id = %q, want 'user'", id)
	}
	resp, err := ReadUserPassResponse(&buf)
	if err != nil {
		t.Fatalf("read response error: %v", err)
	}
	if resp.Status != UserPassSuccess {
		t.Errorf("status = %#x, want success", resp.Status)
	}
}

func TestServerSelectorOnSelectedUserPassFailure(t *testing.T) {
	s := NewServerSelector(Credential{Username: "user", Password: "pass"})
	var buf bytes.Buffer
	if err := NewUserPassRequest(UserPassVersion, "wrong", "creds").Write(&buf); err != nil {
		t.Fatal(err)
	}
	id, err := s.OnSelected(MethodUserPass, &buf)
	if err != ErrAuthFailure {
		t.Errorf("failure: got %v, want ErrAuthFailure", err)
	}
	if id != "" {
		t.Errorf("id = %q, want empty", id)
	}
	resp, err := ReadUserPassResponse(&buf)
	if err != nil {
		t.Fatalf("read response error: %v", err)
	}
	if resp.Status != UserPassFailure {
		t.Errorf("status = %#x, want failure", resp.Status)
	}
}

func TestServerSelectorOnSelectedUserPassReadError(t *testing.T) {
	s := NewServerSelector(Credential{Username: "u", Password: "p"})
	// empty buffer: reading credentials fails
	_, err := s.OnSelected(MethodUserPass, &bytes.Buffer{})
	if err == nil {
		t.Error("expected error reading credentials from empty buffer")
	}
}

func TestServerHandshakeNilSelector(t *testing.T) {
	buf := bytes.NewBuffer([]byte{Version, 1, MethodNoAuth})
	id, err := ServerHandshake(buf, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id != "" {
		t.Errorf("id = %q, want empty", id)
	}
	out := buf.Bytes()
	if len(out) < 2 || out[1] != MethodNoAuth {
		t.Errorf("selected method = %v, want NoAuth", out)
	}
}

func TestServerHandshakeNoAcceptable(t *testing.T) {
	buf := bytes.NewBuffer([]byte{Version, 1, MethodNoAuth})
	selector := NewServerSelector(Credential{Username: "u", Password: "p"})
	_, err := ServerHandshake(buf, selector)
	if err != ErrBadMethod {
		t.Errorf("error: got %v, want ErrBadMethod", err)
	}
	out := buf.Bytes()
	if len(out) < 2 || out[1] != MethodNoAcceptable {
		t.Errorf("selected method = %v, want NoAcceptable", out)
	}
}

func TestServerHandshakeBadVersion(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x04, 1, MethodNoAuth})
	selector := NewServerSelector()
	_, err := ServerHandshake(buf, selector)
	if err != ErrBadVersion {
		t.Errorf("error: got %v, want ErrBadVersion", err)
	}
}

func TestServerHandshakeNoAuthPipe(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	selector := NewServerSelector()
	errCh := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(server, selector)
		errCh <- err
	}()

	if _, err := client.Write([]byte{Version, 1, MethodNoAuth}); err != nil {
		t.Fatal(err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(client, resp[:]); err != nil {
		t.Fatal(err)
	}
	if resp[0] != Version || resp[1] != MethodNoAuth {
		t.Errorf("selected = [%#x, %#x], want [Version, NoAuth]", resp[0], resp[1])
	}
	if err := <-errCh; err != nil {
		t.Fatalf("ServerHandshake error: %v", err)
	}
}

func TestServerHandshakeUserPassSuccessPipe(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	selector := NewServerSelector(Credential{Username: "user", Password: "pass"})
	type result struct {
		id  string
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		id, err := ServerHandshake(server, selector)
		resCh <- result{id, err}
	}()

	if _, err := client.Write([]byte{Version, 1, MethodUserPass}); err != nil {
		t.Fatal(err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(client, sel[:]); err != nil {
		t.Fatal(err)
	}
	if sel[1] != MethodUserPass {
		t.Fatalf("selected = %#x, want UserPass", sel[1])
	}
	if err := NewUserPassRequest(UserPassVersion, "user", "pass").Write(client); err != nil {
		t.Fatal(err)
	}
	authResp, err := ReadUserPassResponse(client)
	if err != nil {
		t.Fatal(err)
	}
	if authResp.Status != UserPassSuccess {
		t.Errorf("status = %#x, want success", authResp.Status)
	}
	r := <-resCh
	if r.err != nil {
		t.Fatalf("ServerHandshake error: %v", r.err)
	}
	if r.id != "user" {
		t.Errorf("id = %q, want 'user'", r.id)
	}
}

type readOKWriteFail struct {
	r *bytes.Buffer
}

func (rw *readOKWriteFail) Read(p []byte) (int, error)  { return rw.r.Read(p) }
func (rw *readOKWriteFail) Write(p []byte) (int, error) { return 0, errors.New("write failed") }

func TestServerHandshakeWriteMethodError(t *testing.T) {
	rw := &readOKWriteFail{r: bytes.NewBuffer([]byte{Version, 1, MethodNoAuth})}
	_, err := ServerHandshake(rw, NewServerSelector())
	if err == nil {
		t.Error("expected write error")
	}
}

func TestServerSelectorOnSelectedUserPassWriteResponseError(t *testing.T) {
	var input bytes.Buffer
	if err := NewUserPassRequest(UserPassVersion, "user", "pass").Write(&input); err != nil {
		t.Fatal(err)
	}
	rw := &readOKWriteFail{r: &input}
	s := NewServerSelector(Credential{Username: "user", Password: "pass"})
	_, err := s.OnSelected(MethodUserPass, rw)
	if err == nil {
		t.Error("expected write response error")
	}
}
