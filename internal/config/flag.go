package config

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"gocks/internal/constant"
)

// DefaultListen is the listener used when the command line carries no -L.
const DefaultListen = ":8181"

// itemKind distinguishes the two ordered command line options.
type itemKind uint8

const (
	itemListen itemKind = iota
	itemUpstream
)

// item is one -L or one comma-expanded -F entry, kept in command line order.
type item struct {
	kind  itemKind
	value string
}

// Flags collects every -L and -F occurrence in command line order. Order
// matters because consecutive -L options form one listen group that shares the
// -F group following it:
//
//	-L a -L b -F p -F q
//
// serves a and b through the chain p -> q, while
//
//	-L a -F p -L b
//
// serves a through p and b directly.
type Flags struct {
	items []item
}

// Listen returns the flag.Value behind -L, to be registered with flag.Var.
func (f *Flags) Listen() flag.Value { return listenValue{flags: f} }

// Upstream returns the flag.Value behind -F, to be registered with flag.Var.
func (f *Flags) Upstream() flag.Value { return upstreamValue{flags: f} }

type listenValue struct{ flags *Flags }

// String implements flag.Value. The default is empty so that the absence of
// -L is distinguishable from an explicitly empty value.
func (v listenValue) String() string { return "" }

// Set implements flag.Value.
func (v listenValue) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("listen address must not be empty")
	}
	v.flags.items = append(v.flags.items, item{kind: itemListen, value: value})
	return nil
}

type upstreamValue struct{ flags *Flags }

// String implements flag.Value.
func (v upstreamValue) String() string { return "" }

// Set implements flag.Value. One occurrence may carry a comma-separated list,
// so both of these append the same two hops:
//
//	-F a -F b
//	-F "a,b"
func (v upstreamValue) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v.flags.items = append(v.flags.items, item{kind: itemUpstream, value: part})
	}
	return nil
}

// Load parses the collected command line values into a Config.
func Load(flags *Flags, idleTimeout time.Duration) (Config, error) {
	if err := ValidateTimeout(idleTimeout); err != nil {
		return Config{}, err
	}

	var items []item
	if flags != nil {
		items = flags.items
	}
	rules, err := buildRules(items)
	if err != nil {
		return Config{}, err
	}
	for i := range rules {
		rules[i].Timeout = idleTimeout
	}
	return Config{Rules: rules, Timeout: idleTimeout}, nil
}

// ValidateTimeout rejects a negative idle timeout. Zero is valid and means the
// tunnel idle timeout is disabled.
func ValidateTimeout(d time.Duration) error {
	if d < 0 {
		return fmt.Errorf("timeout must not be negative: %s", d)
	}
	return nil
}

// buildRules groups the ordered items into rules. Consecutive -L options share
// the -F group that follows them; a new group starts once a rule already has
// an upstream chain and another -L appears. An -F group before any -L becomes
// the default chain for groups that carry none, which keeps the historical
// "-F a -L x" form working.
func buildRules(items []item) ([]Rule, error) {
	var (
		rules        []Rule
		pending      []string
		chain        []string
		defaultChain []string
	)

	flush := func() error {
		effective := chain
		if len(effective) == 0 {
			effective = defaultChain
		}
		for _, raw := range pending {
			if len(rules) >= MaxRules {
				return fmt.Errorf("too many listen rules, at most %d are supported", MaxRules)
			}
			rule, err := newRule(raw, effective)
			if err != nil {
				return fmt.Errorf("rule %d: %w", len(rules)+1, err)
			}
			rules = append(rules, rule)
		}
		pending = nil
		chain = nil
		return nil
	}

	for _, it := range items {
		switch it.kind {
		case itemListen:
			if len(chain) > 0 {
				if err := flush(); err != nil {
					return nil, err
				}
			}
			pending = append(pending, it.value)
		case itemUpstream:
			if len(pending) == 0 && len(chain) == 0 && len(rules) == 0 {
				defaultChain = append(defaultChain, it.value)
			} else {
				chain = append(chain, it.value)
			}
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}

	if len(rules) == 0 {
		rule, err := newRule(DefaultListen, nil)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	for i := range rules {
		rules[i].Label = fmt.Sprintf("%d/%d", i+1, len(rules))
	}
	return rules, nil
}

// newRule parses one listener and validates it together with its chain.
func newRule(listen string, chain []string) (Rule, error) {
	if strings.HasPrefix(listen, ":") {
		listen = constant.Mix + "://" + listen
	}

	var endpoint Endpoint
	if err := ParseEndpoint(listen, &endpoint); err != nil {
		return Rule{}, fmt.Errorf("listen %q: %w", listen, err)
	}
	if endpoint.Addr == "" {
		return Rule{}, fmt.Errorf("listen %q: missing address", listen)
	}

	switch endpoint.Scheme {
	case constant.TCP, constant.UDP:
		if endpoint.Target == "" {
			return Rule{}, fmt.Errorf("listen %q: %s forwarding requires a /target", listen, endpoint.Scheme)
		}
	case constant.HTTP, constant.Socks5, constant.Mix:
		if endpoint.Target != "" {
			return Rule{}, fmt.Errorf("listen %q: %s proxies do not accept a /target", listen, endpoint.Scheme)
		}
	default:
		return Rule{}, fmt.Errorf("listen %q: unsupported scheme %q", listen, endpoint.Scheme)
	}

	upstream, err := buildUpstream(chain)
	if err != nil {
		return Rule{}, fmt.Errorf("listen %q: %w", listen, err)
	}
	if endpoint.Scheme == constant.UDP && len(upstream) > 0 {
		return Rule{}, fmt.Errorf("listen %q: udp port forwarding does not support -F", listen)
	}
	return Rule{Listen: endpoint, Upstream: upstream}, nil
}

// buildUpstream parses the -F values of one chain in dial order: the first
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
