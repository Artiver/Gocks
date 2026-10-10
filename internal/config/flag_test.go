package config

import (
	"strings"
	"testing"
)

// TestForwardListSet verifies that Set splits comma-separated values, trims
// whitespace, ignores empty entries, and accumulates across repeated calls.
func TestForwardListSet(t *testing.T) {
	// single comma-separated string splits into multiple entries
	var l ForwardList
	if err := l.Set("a,b,c"); err != nil {
		t.Fatalf("Set err = %v", err)
	}
	if len(l) != 3 {
		t.Fatalf("len = %d, want 3", len(l))
	}
	if l[0] != "a" || l[1] != "b" || l[2] != "c" {
		t.Errorf("entries = %v, want [a b c]", []string(l))
	}

	// repeated Set calls accumulate
	if err := l.Set("d,e"); err != nil {
		t.Fatalf("Set err = %v", err)
	}
	if len(l) != 5 {
		t.Errorf("len = %d, want 5", len(l))
	}
	if l[3] != "d" || l[4] != "e" {
		t.Errorf("entries = %v, want [a b c d e]", []string(l))
	}

	// empty entries ignored
	var l2 ForwardList
	if err := l2.Set("a,,b"); err != nil {
		t.Fatalf("Set err = %v", err)
	}
	if len(l2) != 2 {
		t.Errorf("len = %d, want 2", len(l2))
	}
	if l2[0] != "a" || l2[1] != "b" {
		t.Errorf("entries = %v, want [a b]", []string(l2))
	}

	// whitespace trimmed
	var l3 ForwardList
	if err := l3.Set("  x  ,  y  "); err != nil {
		t.Fatalf("Set err = %v", err)
	}
	if len(l3) != 2 {
		t.Fatalf("len = %d, want 2", len(l3))
	}
	if l3[0] != "x" || l3[1] != "y" {
		t.Errorf("entries = %v, want [x y]", []string(l3))
	}

	// empty string -> no entries
	var l4 ForwardList
	if err := l4.Set(""); err != nil {
		t.Fatalf("Set err = %v", err)
	}
	if len(l4) != 0 {
		t.Errorf("len = %d, want 0", len(l4))
	}

	// only whitespace and commas -> no entries
	var l5 ForwardList
	if err := l5.Set("  ,  ,  "); err != nil {
		t.Fatalf("Set err = %v", err)
	}
	if len(l5) != 0 {
		t.Errorf("len = %d, want 0", len(l5))
	}
}

// TestForwardListString verifies that String joins entries with commas and
// handles nil and empty receivers safely.
func TestForwardListString(t *testing.T) {
	// nil receiver
	var nilList *ForwardList
	if got := nilList.String(); got != "" {
		t.Errorf("nil String() = %q, want %q", got, "")
	}

	// empty list
	var empty ForwardList
	if got := empty.String(); got != "" {
		t.Errorf("empty String() = %q, want %q", got, "")
	}

	// single entry
	single := ForwardList{"only"}
	if got := single.String(); got != "only" {
		t.Errorf("String() = %q, want %q", got, "only")
	}

	// multiple entries
	l := ForwardList{"a", "b", "c"}
	if got := l.String(); got != "a,b,c" {
		t.Errorf("String() = %q, want %q", got, "a,b,c")
	}
}

// TestBuildForwardChain covers the empty chain, valid socks5/http hops, multiple
// hops, and every error path: unsupported scheme, too many hops, invalid URL,
// and missing address.
func TestBuildForwardChain(t *testing.T) {
	// empty input -> empty chain, no error
	chain, err := BuildForwardChain(nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(chain) != 0 {
		t.Errorf("len = %d, want 0", len(chain))
	}

	// single socks5 hop
	chain, err = BuildForwardChain([]string{"socks5://host:1080"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("len = %d, want 1", len(chain))
	}
	if chain[0].Scheme != "socks5" {
		t.Errorf("Scheme = %q, want %q", chain[0].Scheme, "socks5")
	}
	if chain[0].BindAddr != "host:1080" {
		t.Errorf("BindAddr = %q, want %q", chain[0].BindAddr, "host:1080")
	}

	// single http hop
	chain, err = BuildForwardChain([]string{"http://host:8080"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if chain[0].Scheme != "http" {
		t.Errorf("Scheme = %q, want %q", chain[0].Scheme, "http")
	}

	// multiple hops preserve order
	chain, err = BuildForwardChain([]string{"socks5://a:1080", "http://b:8080"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("len = %d, want 2", len(chain))
	}
	if chain[0].Scheme != "socks5" || chain[1].Scheme != "http" {
		t.Errorf("schemes = %q %q, want socks5 http", chain[0].Scheme, chain[1].Scheme)
	}

	// unsupported scheme (tcp is not allowed in forward chain)
	_, err = BuildForwardChain([]string{"tcp://host:1234"})
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
	if !strings.Contains(err.Error(), "unsupported scheme") {
		t.Errorf("err = %v, want containing %q", err, "unsupported scheme")
	}

	// too many hops
	addrs := make([]string, MaxForwardHops+1)
	for i := range addrs {
		addrs[i] = "socks5://host:1080"
	}
	_, err = BuildForwardChain(addrs)
	if err == nil {
		t.Fatal("expected error for too many hops")
	}
	if !strings.Contains(err.Error(), "at most") {
		t.Errorf("err = %v, want containing %q", err, "at most")
	}

	// invalid URL in a hop
	_, err = BuildForwardChain([]string{"http://[::1"})
	if err == nil {
		t.Fatal("expected error for invalid url")
	}
	if !strings.Contains(err.Error(), "forward hop") {
		t.Errorf("err = %v, want containing %q", err, "forward hop")
	}

	// missing address (empty host)
	_, err = BuildForwardChain([]string{"socks5://"})
	if err == nil {
		t.Fatal("expected error for missing address")
	}
	if !strings.Contains(err.Error(), "missing address") {
		t.Errorf("err = %v, want containing %q", err, "missing address")
	}
}

// TestParseArgsInfo tests the success paths of ParseArgsInfo while saving and
// restoring the package-level globals it mutates. The log.Fatalln error paths
// are intentionally excluded because they call os.Exit.
func TestParseArgsInfo(t *testing.T) {
	// save and restore globals
	oldProxy := ProxyConfig
	oldChain := ForwardChain
	defer func() {
		ProxyConfig = oldProxy
		ForwardChain = oldChain
	}()

	// normal proxy with a forward chain
	ParseArgsInfo("socks5://host:1080", []string{"http://upstream:8080"})
	if ProxyConfig.Scheme != "socks5" {
		t.Errorf("ProxyConfig.Scheme = %q, want %q", ProxyConfig.Scheme, "socks5")
	}
	if ProxyConfig.BindAddr != "host:1080" {
		t.Errorf("ProxyConfig.BindAddr = %q, want %q", ProxyConfig.BindAddr, "host:1080")
	}
	if len(ForwardChain) != 1 {
		t.Fatalf("len(ForwardChain) = %d, want 1", len(ForwardChain))
	}
	if ForwardChain[0].Scheme != "http" {
		t.Errorf("ForwardChain[0].Scheme = %q, want %q", ForwardChain[0].Scheme, "http")
	}

	// colon-prefixed address -> mix:// scheme
	ParseArgsInfo(":1080", nil)
	if ProxyConfig.Scheme != "mix" {
		t.Errorf("ProxyConfig.Scheme = %q, want %q", ProxyConfig.Scheme, "mix")
	}
	if ProxyConfig.BindAddr != ":1080" {
		t.Errorf("ProxyConfig.BindAddr = %q, want %q", ProxyConfig.BindAddr, ":1080")
	}
	if len(ForwardChain) != 0 {
		t.Errorf("len(ForwardChain) = %d, want 0", len(ForwardChain))
	}

	// proxy with auth and no forward chain
	ParseArgsInfo("socks5://user:pass@host:1080", nil)
	if ProxyConfig.Scheme != "socks5" {
		t.Errorf("ProxyConfig.Scheme = %q, want %q", ProxyConfig.Scheme, "socks5")
	}
	if ProxyConfig.Auth == nil {
		t.Fatal("ProxyConfig.Auth = nil, want non-nil")
	}
	if ProxyConfig.Auth.Username != "user" || ProxyConfig.Auth.Password != "pass" {
		t.Errorf("Auth = %v, want {user pass}", ProxyConfig.Auth)
	}
	if len(ForwardChain) != 0 {
		t.Errorf("len(ForwardChain) = %d, want 0", len(ForwardChain))
	}
}
