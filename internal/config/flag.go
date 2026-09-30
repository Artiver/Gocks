package config

import (
	"fmt"
	"log"
	"strings"

	"gocks/internal/constant"
)

// ForwardList is the value behind -F. Every occurrence appends one hop, and a
// single occurrence may carry a comma-separated list, so both of these build
// the same two-hop chain:
//
//	-F socks5://a:1080 -F http://b:8080
//	-F socks5://a:1080,http://b:8080
//
// Empty entries are ignored, so passing -F "" keeps meaning "no upstream".
type ForwardList []string

// String implements flag.Value.
func (l *ForwardList) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, ",")
}

// Set implements flag.Value.
func (l *ForwardList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		*l = append(*l, part)
	}
	return nil
}

func ParseArgsInfo(proxyAddr string, forwardAddrs []string) {
	if strings.HasPrefix(proxyAddr, ":") {
		proxyAddr = "mix://" + proxyAddr
	}

	if err := ParseUrl(proxyAddr, &ProxyConfig); err != nil {
		log.Fatalln(err)
	}

	chain, err := BuildForwardChain(forwardAddrs)
	if err != nil {
		log.Fatalln(err)
	}
	ForwardChain = chain
}

// BuildForwardChain parses -F values into the hop list in dial order: the
// first address is contacted first, the last one reaches the final target.
func BuildForwardChain(forwardAddrs []string) ([]Url, error) {
	if len(forwardAddrs) > MaxForwardHops {
		return nil, fmt.Errorf("forward chain has %d hops, at most %d are supported", len(forwardAddrs), MaxForwardHops)
	}

	var chain []Url
	for i, addr := range forwardAddrs {
		var hop Url
		if err := ParseUrl(addr, &hop); err != nil {
			return nil, fmt.Errorf("forward hop %d (%s): %w", i, addr, err)
		}
		if hop.BindAddr == "" {
			return nil, fmt.Errorf("forward hop %d (%s): missing address", i, addr)
		}
		switch hop.Scheme {
		case constant.Socks5, constant.HTTP:
		default:
			return nil, fmt.Errorf("forward hop %d (%s): unsupported scheme %q", i, addr, hop.Scheme)
		}
		chain = append(chain, hop)
	}
	return chain, nil
}
