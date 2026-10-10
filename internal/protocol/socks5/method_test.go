package socks5

import (
	"bytes"
	"testing"
)

func TestReadMethodsRoundTrip(t *testing.T) {
	methods := [][]byte{
		{MethodNoAuth},
		{MethodNoAuth, MethodUserPass},
		{MethodGSSAPI, MethodUserPass, MethodNoAuth},
	}
	for _, ms := range methods {
		var buf bytes.Buffer
		buf.Write([]byte{Version, byte(len(ms))})
		buf.Write(ms)
		got, err := ReadMethods(&buf)
		if err != nil {
			t.Fatalf("ReadMethods error: %v", err)
		}
		if !bytes.Equal(got, ms) {
			t.Errorf("methods mismatch: %v vs %v", got, ms)
		}
	}
}

func TestWriteMethod(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMethod(MethodNoAuth, &buf); err != nil {
		t.Fatalf("WriteMethod error: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{Version, MethodNoAuth}) {
		t.Errorf("WriteMethod output: %v", buf.Bytes())
	}
}

func TestReadMethodsErrors(t *testing.T) {
	// bad version
	_, err := ReadMethods(bytes.NewReader([]byte{0x04, 1, MethodNoAuth}))
	if err != ErrBadVersion {
		t.Errorf("bad version: got %v, want ErrBadVersion", err)
	}
	// nmethods == 0
	_, err = ReadMethods(bytes.NewReader([]byte{Version, 0}))
	if err != ErrBadMethod {
		t.Errorf("nmethods=0: got %v, want ErrBadMethod", err)
	}
	// truncated methods payload
	_, err = ReadMethods(bytes.NewReader([]byte{Version, 2, MethodNoAuth}))
	if err == nil {
		t.Error("truncated: expected error")
	}
	// truncated header
	_, err = ReadMethods(bytes.NewReader([]byte{Version}))
	if err == nil {
		t.Error("truncated header: expected error")
	}
}

func TestHasMethod(t *testing.T) {
	methods := []byte{MethodNoAuth, MethodUserPass}
	if !HasMethod(methods, MethodNoAuth) {
		t.Error("HasMethod NoAuth should be true")
	}
	if !HasMethod(methods, MethodUserPass) {
		t.Error("HasMethod UserPass should be true")
	}
	if HasMethod(methods, MethodGSSAPI) {
		t.Error("HasMethod GSSAPI should be false")
	}
	if HasMethod(nil, MethodNoAuth) {
		t.Error("HasMethod nil should be false")
	}
	if HasMethod([]byte{}, MethodNoAuth) {
		t.Error("HasMethod empty should be false")
	}
}
