package config

import (
	"flag"
	"strings"
	"testing"

	"gocks/internal/constant"
)

// TestForwardListIsRepeatable guards the behaviour the old single string flag
// lacked: a second -F must extend the chain instead of replacing the first.
func TestForwardListIsRepeatable(t *testing.T) {
	var list ForwardList
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Var(&list, "F", "upstream")

	err := fs.Parse([]string{
		"-F", "socks5://a:1080",
		"-F", "http://b:8080",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"socks5://a:1080", "http://b:8080"}
	if len(list) != len(want) {
		t.Fatalf("list=%v want %v", list, want)
	}
	for i := range want {
		if list[i] != want[i] {
			t.Fatalf("list[%d]=%q want %q", i, list[i], want[i])
		}
	}
}

func TestForwardListSet(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{"single", "socks5://a:1080", []string{"socks5://a:1080"}},
		{"comma separated", "socks5://a:1080,http://b:8080", []string{"socks5://a:1080", "http://b:8080"}},
		{"trims spaces", " socks5://a:1080 , http://b:8080 ", []string{"socks5://a:1080", "http://b:8080"}},
		{"empty value adds nothing", "", nil},
		{"empty entries are skipped", "socks5://a:1080,,http://b:8080", []string{"socks5://a:1080", "http://b:8080"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var list ForwardList
			if err := list.Set(tc.value); err != nil {
				t.Fatalf("Set(%q): %v", tc.value, err)
			}
			if len(list) != len(tc.want) {
				t.Fatalf("list=%v want %v", list, tc.want)
			}
			for i := range tc.want {
				if list[i] != tc.want[i] {
					t.Fatalf("list[%d]=%q want %q", i, list[i], tc.want[i])
				}
			}
		})
	}
}

func TestForwardListString(t *testing.T) {
	list := ForwardList{"socks5://a:1080", "http://b:8080"}
	if got := list.String(); got != "socks5://a:1080,http://b:8080" {
		t.Fatalf("String()=%q", got)
	}

	var empty ForwardList
	if got := empty.String(); got != "" {
		t.Fatalf("String()=%q want empty", got)
	}
}

func TestBuildForwardChainKeepsDialOrder(t *testing.T) {
	chain, err := BuildForwardChain([]string{
		"socks5://user:pass@near.example:1080",
		"http://far.example:8080",
	})
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain=%v want 2 hops", chain)
	}

	// The first -F is the nearest hop, so it is contacted first.
	if chain[0].Scheme != constant.Socks5 || chain[0].BindAddr != "near.example:1080" {
		t.Fatalf("hop[0]=%+v", chain[0])
	}
	if chain[0].Auth == nil || chain[0].Auth.Username != "user" || chain[0].Auth.Password != "pass" {
		t.Fatalf("hop[0] credentials=%+v", chain[0].Auth)
	}
	if chain[1].Scheme != constant.HTTP || chain[1].BindAddr != "far.example:8080" {
		t.Fatalf("hop[1]=%+v", chain[1])
	}
	if chain[1].Auth != nil {
		t.Fatalf("hop[1] should not carry credentials: %+v", chain[1].Auth)
	}
}

func TestBuildForwardChainEmpty(t *testing.T) {
	chain, err := BuildForwardChain(nil)
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	if len(chain) != 0 {
		t.Fatalf("chain=%v want empty", chain)
	}
}

func TestBuildForwardChainErrors(t *testing.T) {
	tests := []struct {
		name  string
		addrs []string
		want  string
	}{
		{"unsupported scheme", []string{"ftp://a:1080"}, "unsupported scheme"},
		{"address without scheme", []string{"192.168.200.1:1080"}, "forward hop 0"},
		{"missing address", []string{"socks5://"}, "missing address"},
		{"failing hop is named", []string{"socks5://a:1080", "ftp://b:8080"}, "forward hop 1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildForwardChain(tc.addrs)
			if err == nil {
				t.Fatalf("BuildForwardChain(%v) should fail", tc.addrs)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%q want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestBuildForwardChainHopLimit(t *testing.T) {
	addrs := make([]string, MaxForwardHops+1)
	for i := range addrs {
		addrs[i] = "socks5://hop:1080"
	}

	if _, err := BuildForwardChain(addrs); err == nil {
		t.Fatal("expected the hop limit to be enforced")
	}
}
