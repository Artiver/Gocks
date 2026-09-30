package socks5

import (
	"bytes"
	"errors"
	"testing"
)

func TestReadMethods(t *testing.T) {
	methods, err := ReadMethods(bytes.NewReader([]byte{Version, 0x02, MethodNoAuth, MethodUserPass}))
	if err != nil {
		t.Fatalf("ReadMethods: %v", err)
	}
	if len(methods) != 2 || methods[0] != MethodNoAuth || methods[1] != MethodUserPass {
		t.Fatalf("unexpected methods: %v", methods)
	}
}

func TestReadMethodsBadVersion(t *testing.T) {
	if _, err := ReadMethods(bytes.NewReader([]byte{0x04, 0x01, 0x00})); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

func TestReadMethodsNoMethods(t *testing.T) {
	if _, err := ReadMethods(bytes.NewReader([]byte{Version, 0x00})); !errors.Is(err, ErrBadMethod) {
		t.Fatalf("want ErrBadMethod, got %v", err)
	}
}

func TestReadMethodsTruncated(t *testing.T) {
	// Announces two methods but only one byte follows.
	if _, err := ReadMethods(bytes.NewReader([]byte{Version, 0x02, MethodNoAuth})); err == nil {
		t.Fatal("want error for truncated methods")
	}
}

func TestReadMethodsTruncatedHeader(t *testing.T) {
	if _, err := ReadMethods(bytes.NewReader([]byte{Version})); err == nil {
		t.Fatal("want error for truncated header")
	}
}

func TestWriteMethod(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMethod(MethodUserPass, &buf); err != nil {
		t.Fatalf("WriteMethod: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{Version, MethodUserPass}) {
		t.Fatalf("unexpected bytes: %v", buf.Bytes())
	}
}

func TestHasMethod(t *testing.T) {
	methods := []byte{MethodNoAuth, MethodUserPass}
	if !HasMethod(methods, MethodUserPass) {
		t.Fatal("expected MethodUserPass to be present")
	}
	if HasMethod(methods, MethodGSSAPI) {
		t.Fatal("did not expect MethodGSSAPI to be present")
	}
}
