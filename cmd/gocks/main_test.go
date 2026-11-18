package main

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"gocks/internal/config"
)

func TestRouteString(t *testing.T) {
	tests := []struct {
		name string
		rule config.Rule
		want string
	}{
		{
			name: "proxy without upstream",
			rule: config.Rule{Listen: config.Endpoint{Scheme: "socks5", Addr: "127.0.0.1:1080"}},
			want: "listen socks5://127.0.0.1:1080 -> target (from request)",
		},
		{
			name: "proxy with upstream chain",
			rule: config.Rule{
				Listen: config.Endpoint{Scheme: "mix", Addr: "127.0.0.1:1080"},
				Upstream: []config.Endpoint{
					{Scheme: "http", Addr: "a:8080", Auth: &config.Auth{Username: "u", Password: "p"}},
					{Scheme: "socks5", Addr: "b:1080"},
				},
			},
			want: "listen mix://127.0.0.1:1080 -> [1] http://a:8080 (auth) -> [2] socks5://b:1080 -> target (from request)",
		},
		{
			name: "forward through one upstream",
			rule: config.Rule{
				Listen:   config.Endpoint{Scheme: "tcp", Addr: "127.0.0.1:8080", Target: "internal:443"},
				Upstream: []config.Endpoint{{Scheme: "socks5", Addr: "b:1080"}},
			},
			want: "listen tcp://127.0.0.1:8080 -> [1] socks5://b:1080 -> target internal:443",
		},
		{
			name: "udp forward with fixed target",
			rule: config.Rule{Listen: config.Endpoint{Scheme: "udp", Addr: "127.0.0.1:5353", Target: "8.8.8.8:53"}},
			want: "listen udp://127.0.0.1:5353 -> target 8.8.8.8:53",
		},
		{
			name: "authenticating listener is marked",
			rule: config.Rule{Listen: config.Endpoint{Scheme: "http", Addr: ":8080", Auth: &config.Auth{Username: "u", Password: "p"}}},
			want: "listen http://:8080 (auth) -> target (from request)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := routeString(tt.rule); got != tt.want {
				t.Fatalf("routeString() = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestRouteStringHidesCredentials(t *testing.T) {
	rule := config.Rule{
		Listen: config.Endpoint{
			Scheme: "socks5",
			Addr:   "127.0.0.1:1080",
			Auth:   &config.Auth{Username: "listener-user", Password: "listener-pass"},
		},
		Upstream: []config.Endpoint{
			{Scheme: "http", Addr: "a:8080", Auth: &config.Auth{Username: "hop-user", Password: "hop-pass"}},
		},
	}

	got := routeString(rule)

	for _, secret := range []string{"listener-user", "listener-pass", "hop-user", "hop-pass"} {
		if strings.Contains(got, secret) {
			t.Fatalf("routeString() = %q; must not contain %q", got, secret)
		}
	}
}

func TestLogStartupPrintsRoutes(t *testing.T) {
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(previous)

	logStartup(config.Config{
		Rules: []config.Rule{
			{
				Label:  "1/2",
				Listen: config.Endpoint{Scheme: "socks5", Addr: "127.0.0.1:8181"},
				Upstream: []config.Endpoint{
					{Scheme: "socks5", Addr: "10.0.0.1:8181", Auth: &config.Auth{Username: "u", Password: "p"}},
				},
			},
			{
				Label:  "2/2",
				Listen: config.Endpoint{Scheme: "tcp", Addr: "127.0.0.1:8080", Target: "internal:443"},
			},
		},
	})

	got := buf.String()
	for _, want := range []string{
		"[rule 1/2] listen socks5://127.0.0.1:8181 -> [1] socks5://10.0.0.1:8181 (auth) -> target (from request)",
		"[rule 2/2] listen tcp://127.0.0.1:8080 -> target internal:443",
		"tunnel idle timeout: disabled",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("logStartup() output = %q; want it to contain %q", got, want)
		}
	}
}
