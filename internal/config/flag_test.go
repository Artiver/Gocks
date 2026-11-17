package config

import (
	"strings"
	"testing"
	"time"
)

// flagsFrom builds the ordered flag container a command line would produce.
// Each argument is written either "L:<listen>" or "F:<upstream>".
func flagsFrom(t *testing.T, args ...string) *Flags {
	t.Helper()
	var f Flags
	for _, arg := range args {
		kind, value, ok := strings.Cut(arg, ":")
		if !ok {
			t.Fatalf("bad test argument %q", arg)
		}
		var err error
		switch kind {
		case "L":
			err = f.Listen().Set(value)
		case "F":
			err = f.Upstream().Set(value)
		default:
			t.Fatalf("bad test argument kind %q", kind)
		}
		if err != nil {
			t.Fatalf("set %q: %v", arg, err)
		}
	}
	return &f
}

// TestLoadSingleRule covers the historical one-rule forms.
func TestLoadSingleRule(t *testing.T) {
	cfg, err := Load(flagsFrom(t, "L:socks5://host:1080", "F:http://upstream:8080"), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("len(Rules) = %d, want 1", len(cfg.Rules))
	}
	rule := cfg.Rules[0]
	if rule.Listen.Scheme != "socks5" {
		t.Errorf("Listen.Scheme = %q, want %q", rule.Listen.Scheme, "socks5")
	}
	if rule.Listen.Addr != "host:1080" {
		t.Errorf("Listen.Addr = %q, want %q", rule.Listen.Addr, "host:1080")
	}
	if len(rule.Upstream) != 1 {
		t.Fatalf("len(Upstream) = %d, want 1", len(rule.Upstream))
	}
	if rule.Upstream[0].Scheme != "http" {
		t.Errorf("Upstream[0].Scheme = %q, want %q", rule.Upstream[0].Scheme, "http")
	}

	// colon-prefixed address -> mix:// scheme
	cfg, err = Load(flagsFrom(t, "L::1080"), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rule = cfg.Rules[0]
	if rule.Listen.Scheme != "mix" {
		t.Errorf("Listen.Scheme = %q, want %q", rule.Listen.Scheme, "mix")
	}
	if rule.Listen.Addr != ":1080" {
		t.Errorf("Listen.Addr = %q, want %q", rule.Listen.Addr, ":1080")
	}
	if len(rule.Upstream) != 0 {
		t.Errorf("len(Upstream) = %d, want 0", len(rule.Upstream))
	}

	// proxy with auth and no upstream chain
	cfg, err = Load(flagsFrom(t, "L:socks5://user:pass@host:1080"), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rule = cfg.Rules[0]
	if rule.Listen.Auth == nil {
		t.Fatal("Listen.Auth = nil, want non-nil")
	}
	if rule.Listen.Auth.Username != "user" || rule.Listen.Auth.Password != "pass" {
		t.Errorf("Auth = %v, want {user pass}", rule.Listen.Auth)
	}

	// no -L at all keeps the historical default listener
	cfg, err = Load(flagsFrom(t), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("len(Rules) = %d, want 1", len(cfg.Rules))
	}
	if cfg.Rules[0].Listen.Scheme != "mix" || cfg.Rules[0].Listen.Addr != ":8181" {
		t.Errorf("default rule = %s://%s, want mix://:8181", cfg.Rules[0].Listen.Scheme, cfg.Rules[0].Listen.Addr)
	}
}

// TestLoadGroupsRules verifies the group semantics: consecutive -L options
// share the -F group that follows them.
func TestLoadGroupsRules(t *testing.T) {
	// The command line from the requirement.
	cfg, err := Load(flagsFrom(t,
		"L:tcp://127.0.0.1:10022/10.0.0.1:22",
		"L:tcp://127.0.0.1:10023/10.0.0.1:23",
		"L:tcp://127.0.0.1:10080/10.0.0.1:80",
		"F:socks5://10.128.123.121:8181",
		"L:socks5://127.0.0.1:18182",
		"F:socks5://10.128.123.122:8181",
		"F:socks5://10.128.123.123:8181",
		"L:socks5://127.0.0.1:18181",
		"F:socks5://10.128.123.122:8181",
	), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules) != 5 {
		t.Fatalf("len(Rules) = %d, want 5", len(cfg.Rules))
	}

	wantChain := [][][]string{
		{{"socks5", "10.128.123.121:8181"}},
		{{"socks5", "10.128.123.121:8181"}},
		{{"socks5", "10.128.123.121:8181"}},
		{{"socks5", "10.128.123.122:8181"}, {"socks5", "10.128.123.123:8181"}},
		{{"socks5", "10.128.123.122:8181"}},
	}
	for i, rule := range cfg.Rules {
		label := i + 1
		if rule.Label != itoa(label)+"/5" {
			t.Errorf("rule %d Label = %q, want %q", i, rule.Label, itoa(label)+"/5")
		}
		got := make([][]string, 0, len(rule.Upstream))
		for _, hop := range rule.Upstream {
			got = append(got, []string{hop.Scheme, hop.Addr})
		}
		if !sameChain(got, wantChain[i]) {
			t.Errorf("rule %d chain = %v, want %v", i+1, got, wantChain[i])
		}
	}

	// two listeners sharing the chain that follows them
	cfg, err = Load(flagsFrom(t, "L:socks5://a:1", "L:socks5://b:2", "F:socks5://p:3"), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(cfg.Rules))
	}
	for i, rule := range cfg.Rules {
		if len(rule.Upstream) != 1 || rule.Upstream[0].Addr != "p:3" {
			t.Errorf("rule %d chain = %v, want [p:3]", i+1, rule.Upstream)
		}
	}

	// a new group starts after a chain was attached
	cfg, err = Load(flagsFrom(t, "L:socks5://a:1", "F:socks5://p:3", "L:socks5://b:2"), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(cfg.Rules))
	}
	if len(cfg.Rules[0].Upstream) != 1 {
		t.Errorf("rule 1 chain = %v, want one hop", cfg.Rules[0].Upstream)
	}
	if len(cfg.Rules[1].Upstream) != 0 {
		t.Errorf("rule 2 chain = %v, want none", cfg.Rules[1].Upstream)
	}

	// repeated -F keeps the dial order
	cfg, err = Load(flagsFrom(t, "L:socks5://a:1", "F:socks5://p:3", "F:http://q:4"), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rule := cfg.Rules[0]
	if len(rule.Upstream) != 2 || rule.Upstream[0].Addr != "p:3" || rule.Upstream[1].Addr != "q:4" {
		t.Errorf("chain = %v, want p:3 -> q:4", rule.Upstream)
	}

	// comma-separated -F is split into hops
	cfg, err = Load(flagsFrom(t, "L:socks5://a:1", "F:socks5://p:3, http://q:4"), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules[0].Upstream) != 2 {
		t.Errorf("chain = %v, want two hops", cfg.Rules[0].Upstream)
	}
}

// TestLoadDefaultChain verifies that -F options before the first -L become the
// default chain of groups that carry none.
func TestLoadDefaultChain(t *testing.T) {
	cfg, err := Load(flagsFrom(t, "F:socks5://p:3", "L:socks5://a:1"), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules) != 1 || len(cfg.Rules[0].Upstream) != 1 || cfg.Rules[0].Upstream[0].Addr != "p:3" {
		t.Errorf("rule = %+v, want chain [p:3]", cfg.Rules)
	}

	cfg, err = Load(flagsFrom(t, "F:socks5://p:3", "F:http://q:4", "L:socks5://a:1"), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules[0].Upstream) != 2 {
		t.Errorf("chain = %v, want two hops", cfg.Rules[0].Upstream)
	}

	// a group with its own chain does not inherit the default
	cfg, err = Load(flagsFrom(t, "F:socks5://p:3", "L:socks5://a:1", "F:http://q:4"), 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules[0].Upstream) != 1 || cfg.Rules[0].Upstream[0].Addr != "q:4" {
		t.Errorf("chain = %v, want [q:4]", cfg.Rules[0].Upstream)
	}
}

// TestLoadErrors covers every validation the loader performs.
func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"negative timeout", nil, "negative"},
		{"invalid listen", []string{"L:http://[::1"}, "listen"},
		{"unsupported listen scheme", []string{"L:foo://:1"}, "unsupported scheme"},
		{"missing listen address", []string{"L:socks5://"}, "missing address"},
		{"tcp without target", []string{"L:tcp://:1"}, "requires a /target"},
		{"udp without target", []string{"L:udp://:1"}, "requires a /target"},
		{"proxy with target", []string{"L:http://:1/x"}, "do not accept a /target"},
		{"unsupported upstream scheme", []string{"L:socks5://:1", "F:tcp://p:2"}, "unsupported scheme"},
		{"upstream missing address", []string{"L:socks5://:1", "F:socks5://"}, "missing address"},
		{"udp with upstream", []string{"L:udp://:1/x", "F:socks5://p:2"}, "does not support -F"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeout := time.Duration(0)
			if tt.name == "negative timeout" {
				timeout = -time.Second
			}
			_, err := Load(flagsFrom(t, tt.args...), timeout)
			if err == nil {
				t.Fatalf("Load err = nil, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

// TestLoadTooManyRules verifies the rule count guard.
func TestLoadTooManyRules(t *testing.T) {
	args := make([]string, MaxRules+1)
	for i := range args {
		args[i] = "L:socks5://127.0.0.1:1"
	}
	_, err := Load(flagsFrom(t, args...), 0)
	if err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("err = %v, want containing %q", err, "at most")
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

// TestLoadTimeout verifies that the idle timeout is stored in the Config and
// copied into every rule.
func TestLoadTimeout(t *testing.T) {
	cfg, err := Load(flagsFrom(t, "L:socks5://a:1", "L:socks5://b:2"), 5*time.Minute)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Timeout != 5*time.Minute {
		t.Errorf("Timeout = %s, want 5m", cfg.Timeout)
	}
	for i, rule := range cfg.Rules {
		if rule.Timeout != 5*time.Minute {
			t.Errorf("rule %d Timeout = %s, want 5m", i+1, rule.Timeout)
		}
	}
}

// TestFlagValues covers the raw flag.Value behaviour.
func TestFlagValues(t *testing.T) {
	var f Flags
	if err := f.Listen().Set("   "); err == nil {
		t.Error("empty listen value accepted, want error")
	}
	if got := f.Listen().String(); got != "" {
		t.Errorf("Listen().String() = %q, want empty", got)
	}
	if got := f.Upstream().String(); got != "" {
		t.Errorf("Upstream().String() = %q, want empty", got)
	}

	if err := f.Upstream().Set("  a  ,  , b "); err != nil {
		t.Fatalf("Upstream().Set: %v", err)
	}
	if len(f.items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(f.items))
	}
	if f.items[0].value != "a" || f.items[1].value != "b" {
		t.Errorf("items = %v, want [a b]", f.items)
	}
}

// TestBuildUpstream covers the empty chain, valid socks5/http hops, multiple
// hops, and every error path.
func TestBuildUpstream(t *testing.T) {
	chain, err := buildUpstream(nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(chain) != 0 {
		t.Errorf("len = %d, want 0", len(chain))
	}

	chain, err = buildUpstream([]string{"socks5://host:1080"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(chain) != 1 || chain[0].Scheme != "socks5" || chain[0].Addr != "host:1080" {
		t.Errorf("chain = %v, want socks5 host:1080", chain)
	}

	chain, err = buildUpstream([]string{"socks5://a:1080", "http://b:8080"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(chain) != 2 || chain[0].Scheme != "socks5" || chain[1].Scheme != "http" {
		t.Errorf("schemes = %v, want socks5 http", chain)
	}

	_, err = buildUpstream([]string{"tcp://host:1234"})
	if err == nil || !strings.Contains(err.Error(), "unsupported scheme") {
		t.Errorf("err = %v, want containing %q", err, "unsupported scheme")
	}

	addrs := make([]string, MaxUpstreamHops+1)
	for i := range addrs {
		addrs[i] = "socks5://host:1080"
	}
	_, err = buildUpstream(addrs)
	if err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("err = %v, want containing %q", err, "at most")
	}
}

// itoa avoids importing strconv just for the label assertions.
func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

func sameChain(got, want [][]string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if len(got[i]) != len(want[i]) {
			return false
		}
		for j := range got[i] {
			if got[i][j] != want[i][j] {
				return false
			}
		}
	}
	return true
}
