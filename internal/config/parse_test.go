package config

import (
	"strings"
	"testing"
)

// TestDefaultPort verifies the default port constant used when an endpoint
// address carries no explicit port.
func TestDefaultPort(t *testing.T) {
	if defaultPort != "80" {
		t.Errorf("defaultPort = %q, want %q", defaultPort, "80")
	}
}

// TestHostWithPort exercises every branch of hostWithPort: empty host, host
// already carrying a port, bare IPv4/IPv6 literals (bracketing + default port),
// plain hostnames, and the invalid multi-colon error path.
func TestHostWithPort(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		want    string
		wantErr bool
		errSub  string
	}{
		{"empty host", "", "", false, ""},
		{"hostname with port", "example.com:8080", "example.com:8080", false, ""},
		{"ipv4 with port", "192.168.1.1:443", "192.168.1.1:443", false, ""},
		{"ipv6 bracketed with port", "[::1]:1080", "[::1]:1080", false, ""},
		{"bare ipv4 no port", "192.168.1.1", "192.168.1.1:80", false, ""},
		{"bare ipv6 no port", "::1", "[::1]:80", false, ""},
		{"bracketed ipv6 no port", "[::1]", "[::1]:80", false, ""},
		{"hostname no port", "example.com", "example.com:80", false, ""},
		{"invalid multi colon", "host:bad:port", "", true, "invalid address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hostWithPort(tt.host)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("hostWithPort(%q) err = nil, want error containing %q", tt.host, tt.errSub)
				}
				if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("hostWithPort(%q) err = %v, want error containing %q", tt.host, err, tt.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("hostWithPort(%q) err = %v, want nil", tt.host, err)
			}
			if got != tt.want {
				t.Errorf("hostWithPort(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

// TestParseUrl covers all schemes (socks5, http, tcp, udp), with and without
// auth, with and without explicit port, IPv4/IPv6 hosts, the /target path form,
// trailing slash, empty-user-with-password, special characters in password, and
// every error path (invalid URL, oversized credentials, invalid escape).
func TestParseUrl(t *testing.T) {
	longUser := strings.Repeat("a", 256)
	longPass := strings.Repeat("p", 256)

	tests := []struct {
		name       string
		input      string
		wantScheme string
		wantBind   string
		wantTran   string
		wantUser   string
		wantPass   string
		wantAuth   bool
		wantErr    bool
		errSub     string
	}{
		// socks5
		{"socks5 no auth", "socks5://host:1080", "socks5", "host:1080", "", "", "", false, false, ""},
		{"socks5 with auth", "socks5://user:pass@host:1080", "socks5", "host:1080", "", "user", "pass", true, false, ""},
		// http
		{"http default port", "http://host", "http", "host:80", "", "", "", false, false, ""},
		{"http with auth default port", "http://user:pass@host", "http", "host:80", "", "user", "pass", true, false, ""},
		// tcp with forward target
		{"tcp with target", "tcp://host:1234/target", "tcp", "host:1234", "target", "", "", false, false, ""},
		// udp trailing slash -> empty TranAddr
		{"udp trailing slash", "udp://host:5678/", "udp", "host:5678", "", "", "", false, false, ""},
		// IPv6 hosts
		{"ipv6 with target", "tcp://[::1]:1080/target", "tcp", "[::1]:1080", "target", "", "", false, false, ""},
		{"ipv6 no target", "socks5://[::1]:1080", "socks5", "[::1]:1080", "", "", "", false, false, ""},
		{"ipv6 default port", "http://[::1]", "http", "[::1]:80", "", "", "", false, false, ""},
		// empty user with password -> no auth (username == "" early return)
		{"empty user with password", "socks5://:pass@host:1080", "socks5", "host:1080", "", "", "", false, false, ""},
		// special characters in password (URL-encoded %40 -> @)
		{"special chars in password", "socks5://user:p%40ss@host:1080", "socks5", "host:1080", "", "user", "p@ss", true, false, ""},
		// error paths
		{"invalid url", "http://[::1", "", "", "", "", "", false, true, "missing"},
		{"username too long", "socks5://" + longUser + "@host:1080", "", "", "", "", "", false, true, "255 bytes"},
		{"password too long", "socks5://user:" + longPass + "@host:1080", "", "", "", "", "", false, true, "255 bytes"},
		{"invalid escape in password", "socks5://user:p%25zz@host:1080", "", "", "", "", "", false, true, "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var arg Url
			err := ParseUrl(tt.input, &arg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseUrl(%q) err = nil, want error", tt.input)
				}
				if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("ParseUrl(%q) err = %v, want error containing %q", tt.input, err, tt.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseUrl(%q) err = %v, want nil", tt.input, err)
			}
			if arg.Scheme != tt.wantScheme {
				t.Errorf("Scheme = %q, want %q", arg.Scheme, tt.wantScheme)
			}
			if arg.BindAddr != tt.wantBind {
				t.Errorf("BindAddr = %q, want %q", arg.BindAddr, tt.wantBind)
			}
			if arg.TranAddr != tt.wantTran {
				t.Errorf("TranAddr = %q, want %q", arg.TranAddr, tt.wantTran)
			}
			if tt.wantAuth {
				if arg.Auth == nil {
					t.Fatalf("Auth = nil, want non-nil")
				}
				if arg.Auth.Username != tt.wantUser {
					t.Errorf("Auth.Username = %q, want %q", arg.Auth.Username, tt.wantUser)
				}
				if arg.Auth.Password != tt.wantPass {
					t.Errorf("Auth.Password = %q, want %q", arg.Auth.Password, tt.wantPass)
				}
			} else {
				if arg.Auth != nil {
					t.Errorf("Auth = %v, want nil", arg.Auth)
				}
			}
		})
	}
}
