package socks5

import (
	"errors"
	"gocks/internal/constant"
	"net"
	"testing"
	"time"
)

func TestBuildFailureResponse(t *testing.T) {
	resp := buildFailureResponse(0x05)
	if resp[0] != constant.Socks5Version {
		t.Error("wrong version")
	}
	if resp[1] != 0x05 {
		t.Error("wrong rep code")
	}
	if len(resp) != 10 {
		t.Error("wrong response length")
	}
}

func TestMapDialErrorToRepNil(t *testing.T) {
	if rep := mapDialErrorToRep(nil); rep != 0x00 {
		t.Fatalf("expected 0x00, got 0x%02x", rep)
	}
}

func TestMapDialErrorToRepTimeout(t *testing.T) {
	err := errors.New("i/o timeout")
	if rep := mapDialErrorToRep(err); rep != 0x06 {
		t.Fatalf("expected 0x06, got 0x%02x", rep)
	}
}

func TestMapDialErrorToRepNetTimeout(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	tcpLn := ln.(*net.TCPListener)
	_ = tcpLn.SetDeadline(time.Now())
	_, err := tcpLn.Accept()
	if err == nil {
		t.Skip("no timeout error")
	}
	if rep := mapDialErrorToRep(err); rep != 0x06 {
		t.Fatalf("expected 0x06 for net timeout, got 0x%02x", rep)
	}
}

func TestMapDialErrorToRepRefused(t *testing.T) {
	err := errors.New("connection refused")
	if rep := mapDialErrorToRep(err); rep != 0x05 {
		t.Fatalf("expected 0x05, got 0x%02x", rep)
	}
}

func TestMapDialErrorToRepUnreachable(t *testing.T) {
	err := errors.New("network unreachable")
	if rep := mapDialErrorToRep(err); rep != 0x03 {
		t.Fatalf("expected 0x03, got 0x%02x", rep)
	}
}

func TestMapDialErrorToRepNoRoute(t *testing.T) {
	err := errors.New("no route to host")
	if rep := mapDialErrorToRep(err); rep != 0x04 {
		t.Fatalf("expected 0x04, got 0x%02x", rep)
	}
}

func TestMapDialErrorToRepGeneral(t *testing.T) {
	err := errors.New("some unknown error")
	if rep := mapDialErrorToRep(err); rep != 0x01 {
		t.Fatalf("expected 0x01, got 0x%02x", rep)
	}
}
