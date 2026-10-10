package socks5

import (
	"bytes"
	"testing"
)

func TestUserPassRequestWriteReadRoundTrip(t *testing.T) {
	cases := []struct {
		username string
		password string
	}{
		{"user", "pass"},
		{"", ""},
		{"", "pass"},
		{"user", ""},
		{"longusername", "longpassword"},
	}
	for _, c := range cases {
		req := NewUserPassRequest(UserPassVersion, c.username, c.password)
		var buf bytes.Buffer
		if err := req.Write(&buf); err != nil {
			t.Fatalf("Write error: %v", err)
		}
		got, err := ReadUserPassRequest(&buf)
		if err != nil {
			t.Fatalf("ReadUserPassRequest error: %v", err)
		}
		if got.Username != c.username {
			t.Errorf("Username mismatch: %q vs %q", got.Username, c.username)
		}
		if got.Password != c.password {
			t.Errorf("Password mismatch: %q vs %q", got.Password, c.password)
		}
		if got.Version != UserPassVersion {
			t.Errorf("Version mismatch: %#x", got.Version)
		}
	}
}

func TestUserPassRequestWriteOversize(t *testing.T) {
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'x'
	}
	// oversize username
	req := NewUserPassRequest(UserPassVersion, string(long), "pass")
	var buf bytes.Buffer
	if err := req.Write(&buf); err != ErrBadFormat {
		t.Errorf("oversize username: got %v, want ErrBadFormat", err)
	}
	// oversize password
	req2 := NewUserPassRequest(UserPassVersion, "user", string(long))
	var buf2 bytes.Buffer
	if err := req2.Write(&buf2); err != ErrBadFormat {
		t.Errorf("oversize password: got %v, want ErrBadFormat", err)
	}
}

func TestReadUserPassRequestErrors(t *testing.T) {
	// bad version
	_, err := ReadUserPassRequest(bytes.NewReader([]byte{0x02, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'}))
	if err != ErrBadVersion {
		t.Errorf("bad version: got %v, want ErrBadVersion", err)
	}
	// truncated header
	_, err = ReadUserPassRequest(bytes.NewReader([]byte{UserPassVersion}))
	if err == nil {
		t.Error("truncated header: expected error")
	}
	// truncated username
	_, err = ReadUserPassRequest(bytes.NewReader([]byte{UserPassVersion, 5, 'a', 'b'}))
	if err == nil {
		t.Error("truncated username: expected error")
	}
	// truncated password length byte
	_, err = ReadUserPassRequest(bytes.NewReader([]byte{UserPassVersion, 2, 'a', 'b'}))
	if err == nil {
		t.Error("truncated password length: expected error")
	}
	// truncated password body
	_, err = ReadUserPassRequest(bytes.NewReader([]byte{UserPassVersion, 2, 'a', 'b', 5, 'x', 'y'}))
	if err == nil {
		t.Error("truncated password: expected error")
	}
}

func TestUserPassResponseWriteReadRoundTrip(t *testing.T) {
	for _, status := range []byte{UserPassSuccess, UserPassFailure} {
		res := NewUserPassResponse(UserPassVersion, status)
		var buf bytes.Buffer
		if err := res.Write(&buf); err != nil {
			t.Fatalf("Write error: %v", err)
		}
		got, err := ReadUserPassResponse(&buf)
		if err != nil {
			t.Fatalf("ReadUserPassResponse error: %v", err)
		}
		if got.Status != status {
			t.Errorf("Status mismatch: %#x vs %#x", got.Status, status)
		}
		if got.Version != UserPassVersion {
			t.Errorf("Version mismatch: %#x", got.Version)
		}
	}
}

func TestReadUserPassResponseErrors(t *testing.T) {
	// bad version
	_, err := ReadUserPassResponse(bytes.NewReader([]byte{0x02, UserPassSuccess}))
	if err != ErrBadVersion {
		t.Errorf("bad version: got %v, want ErrBadVersion", err)
	}
	// truncated
	_, err = ReadUserPassResponse(bytes.NewReader([]byte{UserPassVersion}))
	if err == nil {
		t.Error("truncated: expected error")
	}
}
