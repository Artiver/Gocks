package socks5

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestUserPassRequestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := NewUserPassRequest(UserPassVersion, "alice", "s3cret").Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}

	req, err := ReadUserPassRequest(&buf)
	if err != nil {
		t.Fatalf("ReadUserPassRequest: %v", err)
	}
	if req.Version != UserPassVersion || req.Username != "alice" || req.Password != "s3cret" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestUserPassRequestEmptyCredentials(t *testing.T) {
	var buf bytes.Buffer
	if err := NewUserPassRequest(UserPassVersion, "", "").Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	req, err := ReadUserPassRequest(&buf)
	if err != nil {
		t.Fatalf("ReadUserPassRequest: %v", err)
	}
	if req.Username != "" || req.Password != "" {
		t.Fatalf("expected empty credentials, got %+v", req)
	}
}

func TestUserPassRequestFragmented(t *testing.T) {
	var buf bytes.Buffer
	if err := NewUserPassRequest(UserPassVersion, "bob", "hunter2").Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	wire := buf.Bytes()

	// Feed the request one byte at a time to emulate TCP fragmentation.
	req, err := ReadUserPassRequest(&oneByteReader{data: wire})
	if err != nil {
		t.Fatalf("ReadUserPassRequest fragmented: %v", err)
	}
	if req.Username != "bob" || req.Password != "hunter2" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestUserPassRequestBadVersion(t *testing.T) {
	var buf bytes.Buffer
	if err := NewUserPassRequest(UserPassVersion, "u", "p").Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	wire := buf.Bytes()
	wire[0] = 0x02
	if _, err := ReadUserPassRequest(bytes.NewReader(wire)); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

func TestUserPassRequestTruncated(t *testing.T) {
	// ULEN=10 but only 3 username bytes present.
	if _, err := ReadUserPassRequest(bytes.NewReader([]byte{UserPassVersion, 10, 'a', 'b', 'c'})); err == nil {
		t.Fatal("want error for truncated username")
	}
}

func TestUserPassRequestWriteOversize(t *testing.T) {
	var buf bytes.Buffer
	err := NewUserPassRequest(UserPassVersion, strings.Repeat("u", 256), "p").Write(&buf)
	if !errors.Is(err, ErrBadFormat) {
		t.Fatalf("want ErrBadFormat, got %v", err)
	}
}

func TestUserPassResponseRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := NewUserPassResponse(UserPassVersion, UserPassSuccess).Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	res, err := ReadUserPassResponse(&buf)
	if err != nil {
		t.Fatalf("ReadUserPassResponse: %v", err)
	}
	if res.Version != UserPassVersion || res.Status != UserPassSuccess {
		t.Fatalf("unexpected response: %+v", res)
	}
}

func TestUserPassResponseBadVersion(t *testing.T) {
	if _, err := ReadUserPassResponse(bytes.NewReader([]byte{0x02, 0x00})); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}
