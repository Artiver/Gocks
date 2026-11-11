package config

import (
	"strings"
	"testing"
	"time"
)

// TestUpstreamListSet verifies that Set splits comma-separated values, trims
// whitespace, ignores empty entries, and accumulates across repeated calls.
func TestUpstreamListSet(t *testing.T) {
	// single comma-separated string splits into multiple entries
	var l UpstreamList
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
	var l2 UpstreamList
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
	var l3 UpstreamList
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
	var l4 UpstreamList
	if err := l4.Set(""); err != nil {
		t.Fatalf("Set err = %v", err)
	}
	if len(l4) != 0 {
		t.Errorf("len = %d, want 0", len(l4))
	}

	// only whitespace and commas -> no entries
	var l5 UpstreamList
	if err := l5.Set("  ,  ,  "); err != nil {
		t.Fatalf("Set err = %v", err)
	}
	if len(l5) != 0 {
		t.Errorf("len = %d, want 0", len(l5))
	}
}

// TestUpstreamListString verifies that String joins entries with commas and
// handles nil and empty receivers safely.
func TestUpstreamListString(t *testing.T) {
	// nil receiver
	var nilList *UpstreamList
	if got := nilList.String(); got != "" {
		t.Errorf("nil String() = %q, want %q", got, "")
	}

	// empty list
	var empty UpstreamList
	if got := empty.String(); got != "" {
		t.Errorf("empty String() = %q, want %q", got, "")
	}

	// single entry
	single := UpstreamList{"only"}
	if got := single.String(); got != "only" {
		t.Errorf("String() = %q, want %q", got, "only")
	}

	// multiple entries
	l := UpstreamList{"a", "b", "c"}
	if got := l.String(); got != "a,b,c" {
		t.Errorf("String() = %q, want %q", got, "a,b,c")
	}
}

// TestBuildUpstream covers the empty chain, valid socks5/http hops, multiple
// hops, and every error path: unsupported scheme, too many hops, invalid URL,
// and missing address.
func TestBuildUpstream(t *testing.T) {
	// empty input -> empty chain, no error
	chain, err := buildUpstream(nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(chain) != 0 {
		t.Errorf("len = %d, want 0", len(chain))
	}

	// single socks5 hop
	chain, err = buildUpstream([]string{"socks5://host:1080"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("len = %d, want 1", len(chain))
	}
	if chain[0].Scheme != "socks5" {
		t.Errorf("Scheme = %q, want %q", chain[0].Scheme, "socks5")
	}
	if chain[0].Addr != "host:1080" {
		t.Errorf("Addr = %q, want %q", chain[0].Addr, "host:1080")
	}

	// single http hop
	chain, err = buildUpstream([]string{"http://host:8080"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if chain[0].Scheme != "http" {
		t.Errorf("Scheme = %q, want %q", chain[0].Scheme, "http")
	}

	// multiple hops preserve order
	chain, err = buildUpstream([]string{"socks5://a:1080", "http://b:8080"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("len = %d, want 2", len(chain))
	}
	if chain[0].Scheme != "socks5" || chain[1].Scheme != "http" {
		t.Errorf("schemes = %q %q, want socks5 http", chain[0].Scheme, chain[1].Scheme)
	}

	// unsupported scheme (tcp is not allowed in the upstream chain)
	_, err = buildUpstream([]string{"tcp://host:1234"})
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
	if !strings.Contains(err.Error(), "unsupported scheme") {
		t.Errorf("err = %v, want containing %q", err, "unsupported scheme")
	}

	// too many hops
	addrs := make([]string, MaxUpstreamHops+1)
	for i := range addrs {
		addrs[i] = "socks5://host:1080"
	}
	_, err = buildUpstream(addrs)
	if err == nil {
		t.Fatal("expected error for too many hops")
	}
	if !strings.Contains(err.Error(), "at most") {
		t.Errorf("err = %v, want containing %q", err, "at most")
	}

	// invalid URL in a hop
	_, err = buildUpstream([]string{"http://[::1"})
	if err == nil {
		t.Fatal("expected error for invalid url")
	}
	if !strings.Contains(err.Error(), "upstream hop") {
		t.Errorf("err = %v, want containing %q", err, "upstream hop")
	}

	// missing address (empty host)
	_, err = buildUpstream([]string{"socks5://"})
	if err == nil {
		t.Fatal("expected error for missing address")
	}
	if !strings.Contains(err.Error(), "missing address") {
		t.Errorf("err = %v, want containing %q", err, "missing address")
	}
}

// TestLoad tests the success paths of Load.
func TestLoad(t *testing.T) {
	// normal proxy with an upstream chain
	cfg, err := Load("socks5://host:1080", []string{"http://upstream:8080"}, 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen.Scheme != "socks5" {
		t.Errorf("Listen.Scheme = %q, want %q", cfg.Listen.Scheme, "socks5")
	}
	if cfg.Listen.Addr != "host:1080" {
		t.Errorf("Listen.Addr = %q, want %q", cfg.Listen.Addr, "host:1080")
	}
	if len(cfg.Upstream) != 1 {
		t.Fatalf("len(Upstream) = %d, want 1", len(cfg.Upstream))
	}
	if cfg.Upstream[0].Scheme != "http" {
		t.Errorf("Upstream[0].Scheme = %q, want %q", cfg.Upstream[0].Scheme, "http")
	}

	// colon-prefixed address -> mix:// scheme
	cfg, err = Load(":1080", nil, 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen.Scheme != "mix" {
		t.Errorf("Listen.Scheme = %q, want %q", cfg.Listen.Scheme, "mix")
	}
	if cfg.Listen.Addr != ":1080" {
		t.Errorf("Listen.Addr = %q, want %q", cfg.Listen.Addr, ":1080")
	}
	if len(cfg.Upstream) != 0 {
		t.Errorf("len(Upstream) = %d, want 0", len(cfg.Upstream))
	}

	// proxy with auth and no upstream chain
	cfg, err = Load("socks5://user:pass@host:1080", nil, 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen.Scheme != "socks5" {
		t.Errorf("Listen.Scheme = %q, want %q", cfg.Listen.Scheme, "socks5")
	}
	if cfg.Listen.Auth == nil {
		t.Fatal("Listen.Auth = nil, want non-nil")
	}
	if cfg.Listen.Auth.Username != "user" || cfg.Listen.Auth.Password != "pass" {
		t.Errorf("Auth = %v, want {user pass}", cfg.Listen.Auth)
	}
	if len(cfg.Upstream) != 0 {
		t.Errorf("len(Upstream) = %d, want 0", len(cfg.Upstream))
	}
}

// TestLoadErrors verifies that invalid command line values are returned as
// errors instead of terminating the process.
func TestLoadErrors(t *testing.T) {
	if _, err := Load(":1080", nil, -time.Second); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Errorf("negative timeout err = %v, want containing %q", err, "negative")
	}
	if _, err := Load("http://[::1", nil, 0); err == nil {
		t.Error("invalid listen address err = nil, want error")
	}
	if _, err := Load(":1080", []string{"tcp://host:1"}, 0); err == nil {
		t.Error("unsupported upstream scheme err = nil, want error")
	}
}

// TestValidateTimeout verifies that zero and positive durations pass and that a
// negative duration is rejected.
func TestValidateTimeout(t *testing.T) {
	for _, d := range []time.Duration{0, time.Second, 5 * time.Minute} {
		if err := ValidateTimeout(d); err != nil {
			t.Errorf("ValidateTimeout(%s) = %v, want nil", d, err)
		}
	}

	err := ValidateTimeout(-time.Second)
	if err == nil {
		t.Fatal("ValidateTimeout(-1s) = nil, want error")
	}
	if !strings.Contains(err.Error(), "negative") {
		t.Errorf("err = %v, want containing %q", err, "negative")
	}
}

// TestLoadTimeout verifies that the idle timeout is stored in the Config.
func TestLoadTimeout(t *testing.T) {
	cfg, err := Load(":1080", nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Timeout != 5*time.Minute {
		t.Errorf("Timeout = %s, want 5m", cfg.Timeout)
	}

	cfg, err = Load(":1080", nil, 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Timeout != 0 {
		t.Errorf("Timeout = %s, want 0", cfg.Timeout)
	}
}
