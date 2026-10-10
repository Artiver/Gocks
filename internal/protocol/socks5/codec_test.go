package socks5

import "testing"

func TestReprString(t *testing.T) {
	cases := []struct {
		rep  byte
		want string
	}{
		{RepSucceeded, "succeeded"},
		{RepFailure, "general failure"},
		{RepNotAllowed, "not allowed"},
		{RepNetUnreachable, "network unreachable"},
		{RepHostUnreachable, "host unreachable"},
		{RepConnRefused, "connection refused"},
		{RepTTLExpired, "TTL expired"},
		{RepCmdUnsupported, "command not supported"},
		{RepAddrUnsupported, "address type not supported"},
		{0x99, "unknown"},
	}
	for _, c := range cases {
		if got := ReprString(c.rep); got != c.want {
			t.Errorf("ReprString(%#x) = %q, want %q", c.rep, got, c.want)
		}
	}
}

func TestConstants(t *testing.T) {
	if Version != 0x05 {
		t.Errorf("Version = %#x, want 0x05", Version)
	}
	if UserPassVersion != 0x01 {
		t.Errorf("UserPassVersion = %#x, want 0x01", UserPassVersion)
	}
	if MethodNoAuth != 0x00 || MethodGSSAPI != 0x01 || MethodUserPass != 0x02 || MethodNoAcceptable != 0xFF {
		t.Error("method constants mismatch with RFC 1928")
	}
	if CmdConnect != 0x01 || CmdBind != 0x02 || CmdUDP != 0x03 {
		t.Error("command constants mismatch with RFC 1928")
	}
	if AddrIPv4 != 0x01 || AddrDomain != 0x03 || AddrIPv6 != 0x04 {
		t.Error("address type constants mismatch with RFC 1928")
	}
	if UserPassSuccess != 0x00 || UserPassFailure != 0x01 {
		t.Error("user/pass status constants mismatch with RFC 1929")
	}
}
