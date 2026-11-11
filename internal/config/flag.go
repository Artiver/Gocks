package config

import (
	"fmt"
	"strings"
	"time"

	"gocks/internal/constant"
)

// UpstreamList is the value behind -F. Every occurrence appends one hop, and a
// single occurrence may carry a comma-separated list, so both of these build
// the same two-hop chain:
//
//	-F socks5://a:1080 -F http://b:8080
//	-F socks5://a:1080,http://b:8080
//
// Empty entries are ignored, so passing -F "" keeps meaning "no upstream".
type UpstreamList []string

// String implements flag.Value.
func (l *UpstreamList) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, ",")
}

// Set implements flag.Value.
func (l *UpstreamList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		*l = append(*l, part)
	}
	return nil
}

// Load parses the command line values into a Config.
func Load(proxyAddr string, upstreamAddrs []string, idleTimeout time.Duration) (Config, error) {
	if err := ValidateTimeout(idleTimeout); err != nil {
		return Config{}, err
	}

	if strings.HasPrefix(proxyAddr, ":") {
		proxyAddr = "mix://" + proxyAddr
	}

	var cfg Config
	if err := ParseEndpoint(proxyAddr, &cfg.Listen); err != nil {
		return Config{}, err
	}

	upstream, err := buildUpstream(upstreamAddrs)
	if err != nil {
		return Config{}, err
	}
	cfg.Upstream = upstream
	cfg.Timeout = idleTimeout
	return cfg, nil
}

// ValidateTimeout rejects a negative idle timeout. Zero is valid and means the
// tunnel idle timeout is disabled.
func ValidateTimeout(d time.Duration) error {
	if d < 0 {
		return fmt.Errorf("timeout must not be negative: %s", d)
	}
	return nil
}

// buildUpstream parses -F values into the hop list in dial order: the first
// address is contacted first, the last one reaches the final target.
func buildUpstream(upstreamAddrs []string) ([]Endpoint, error) {
	if len(upstreamAddrs) > MaxUpstreamHops {
		return nil, fmt.Errorf("upstream chain has %d hops, at most %d are supported", len(upstreamAddrs), MaxUpstreamHops)
	}

	var chain []Endpoint
	for i, addr := range upstreamAddrs {
		var hop Endpoint
		if err := ParseEndpoint(addr, &hop); err != nil {
			return nil, fmt.Errorf("upstream hop %d (%s): %w", i, addr, err)
		}
		if hop.Addr == "" {
			return nil, fmt.Errorf("upstream hop %d (%s): missing address", i, addr)
		}
		switch hop.Scheme {
		case constant.Socks5, constant.HTTP:
		default:
			return nil, fmt.Errorf("upstream hop %d (%s): unsupported scheme %q", i, addr, hop.Scheme)
		}
		chain = append(chain, hop)
	}
	return chain, nil
}
