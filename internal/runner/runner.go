// Package runner owns the lifecycle of every configured listen rule. It binds
// all listeners first, serves them concurrently, and tears them down together.
package runner

import (
	"context"
	"errors"
	"fmt"
	"net"

	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/proxy/http"
	"gocks/internal/proxy/mix"
	"gocks/internal/proxy/socks5"
	"gocks/internal/transport/tcp"
	"gocks/internal/transport/udp"
)

// bound is one rule together with its pre-bound listener.
type bound struct {
	rule config.Rule
	tcp  net.Listener
	udp  net.PacketConn
}

func (b *bound) close() {
	if b.tcp != nil {
		b.tcp.Close()
	}
	if b.udp != nil {
		b.udp.Close()
	}
}

// Run serves every rule in cfg until ctx is cancelled. Every listener is bound
// before any of them begins serving, so a port conflict aborts the start
// instead of leaving the process half-running.
func Run(ctx context.Context, cfg config.Config) error {
	if len(cfg.Rules) == 0 {
		return errors.New("no listen rules configured")
	}
	if err := checkConflicts(cfg.Rules); err != nil {
		return err
	}

	all := make([]*bound, 0, len(cfg.Rules))
	closeAll := func() {
		for _, b := range all {
			b.close()
		}
	}
	for i, rule := range cfg.Rules {
		b, err := bind(rule)
		if err != nil {
			closeAll()
			return fmt.Errorf("rule %d/%d (%s://%s): %w", i+1, len(cfg.Rules), rule.Listen.Scheme, rule.Listen.Addr, err)
		}
		all = append(all, b)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer closeAll()

	// Release every listener as soon as the run is cancelled, so no rule can
	// stay blocked on a socket another rule already gave up on.
	go func() {
		<-ctx.Done()
		closeAll()
	}()

	errCh := make(chan error, len(all))
	for _, b := range all {
		b := b
		go func() {
			if err := serve(ctx, b); err != nil && ctx.Err() == nil {
				errCh <- err
				cancel()
				return
			}
			errCh <- nil
		}()
	}

	var firstErr error
	for range all {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// checkConflicts rejects rules that bind the exact same address on the same
// transport. Wildcard-vs-specific overlaps are left to the operating system,
// which rejects them during the pre-bind instead.
func checkConflicts(rules []config.Rule) error {
	seen := make(map[string]int, len(rules))
	for i, rule := range rules {
		network := "tcp"
		if rule.Listen.Scheme == constant.UDP {
			network = "udp"
		}
		key := network + "://" + rule.Listen.Addr
		if first, ok := seen[key]; ok {
			return fmt.Errorf("rule %d and rule %d both listen on %s %s", first+1, i+1, network, rule.Listen.Addr)
		}
		seen[key] = i
	}
	return nil
}

// bind reserves the listener of one rule without serving it.
func bind(rule config.Rule) (*bound, error) {
	switch rule.Listen.Scheme {
	case constant.UDP:
		pc, err := net.ListenPacket("udp", rule.Listen.Addr)
		if err != nil {
			return nil, err
		}
		return &bound{rule: rule, udp: pc}, nil

	case constant.TCP, constant.HTTP, constant.Socks5, constant.Mix:
		ln, err := net.Listen("tcp", rule.Listen.Addr)
		if err != nil {
			return nil, err
		}
		return &bound{rule: rule, tcp: ln}, nil

	default:
		return nil, fmt.Errorf("unsupported listen scheme %q", rule.Listen.Scheme)
	}
}

func serve(ctx context.Context, b *bound) error {
	switch b.rule.Listen.Scheme {
	case constant.TCP:
		return tcp.Serve(ctx, b.rule, b.tcp)
	case constant.UDP:
		return udp.ServePacket(ctx, b.rule, b.udp)
	case constant.HTTP:
		return http.Serve(ctx, b.rule, b.tcp)
	case constant.Socks5:
		return socks5.Serve(ctx, b.rule, b.tcp)
	case constant.Mix:
		return mix.Serve(ctx, b.rule, b.tcp)
	default:
		return fmt.Errorf("unsupported listen scheme %q", b.rule.Listen.Scheme)
	}
}
