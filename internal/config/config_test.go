package config

import (
	"encoding/base64"
	"testing"

	"gocks/internal/constant"
)

// TestProxyAuthorization verifies the Proxy-Authorization header value for
// normal credentials, empty credentials, and the nil-receiver safety guard.
func TestProxyAuthorization(t *testing.T) {
	// nil receiver -> empty string (safety guard)
	var nilAuth *Auth
	if got := nilAuth.ProxyAuthorization(); got != "" {
		t.Errorf("nil auth: ProxyAuthorization() = %q, want %q", got, "")
	}

	// normal credentials
	auth := &Auth{Username: "user", Password: "pass"}
	want := constant.BasicAuthPrefix + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if got := auth.ProxyAuthorization(); got != want {
		t.Errorf("ProxyAuthorization() = %q, want %q", got, want)
	}
	// verify the concrete base64 value to guard against encoding regressions
	if got := auth.ProxyAuthorization(); got != "Basic dXNlcjpwYXNz" {
		t.Errorf("ProxyAuthorization() = %q, want %q", got, "Basic dXNlcjpwYXNz")
	}

	// empty credentials -> base64 of ":"
	empty := &Auth{}
	want = constant.BasicAuthPrefix + base64.StdEncoding.EncodeToString([]byte(":"))
	if got := empty.ProxyAuthorization(); got != want {
		t.Errorf("ProxyAuthorization() = %q, want %q", got, want)
	}

	// credentials with special characters
	special := &Auth{Username: "u@ser", Password: "p:ass"}
	want = constant.BasicAuthPrefix + base64.StdEncoding.EncodeToString([]byte("u@ser:p:ass"))
	if got := special.ProxyAuthorization(); got != want {
		t.Errorf("ProxyAuthorization() = %q, want %q", got, want)
	}
}
