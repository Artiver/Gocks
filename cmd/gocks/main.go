package main

import (
	"context"
	"flag"
	"fmt"
	"gocks/internal/config"
	"gocks/internal/logging"
	"gocks/internal/runner"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	var (
		ruleFlags   config.Flags
		idleTimeout time.Duration
	)

	// Logging must never wait on the console: cmd.exe suspends writes while
	// the user has text selected, and a handler blocked there looks like a
	// dead process.
	sink := logging.New(os.Stderr, logging.DefaultQueueSize)
	log.SetOutput(sink)
	flag.CommandLine.SetOutput(sink)
	defer sink.Close(logging.DefaultCloseTimeout)

	flag.Var(ruleFlags.Listen(), "L", "Listen rule (repeatable; consecutive -L options share the following -F group; default :8181)")
	flag.Var(ruleFlags.Upstream(), "F", "Upstream proxy address (repeatable, or a comma-separated list; nearest hop first)")
	flag.DurationVar(&idleTimeout, "timeout", 0, "Tunnel idle timeout (e.g. 30s, 5m); 0 disables it")

	// @file arguments must be expanded before flag parsing: the standard
	// library stops parsing options at the first non-option argument.
	args, err := config.ExpandArgs(os.Args[1:])
	if err != nil {
		fatal(sink, err)
	}
	flag.CommandLine.Parse(args)

	log.SetFlags(config.LogFlags)

	cfg, err := config.Load(&ruleFlags, idleTimeout)
	if err != nil {
		fatal(sink, err)
	}
	for i := range cfg.Rules {
		cfg.Rules[i].LogOutput = sink
	}
	logStartup(cfg)

	// Shut down cleanly on Ctrl+C / SIGTERM by cancelling the run context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runner.Run(ctx, cfg); err != nil {
		fatal(sink, err)
	}
	log.Println("shutdown complete")
}

// fatal reports err and exits. It never waits on the console: a stalled
// terminal must not keep the process alive, so the sink is flushed with a
// timeout and the remaining lines are dropped if it does not come back.
func fatal(sink *logging.Sink, err error) {
	log.Println(err)
	sink.Close(logging.DefaultCloseTimeout)
	os.Exit(1)
}

func logStartup(cfg config.Config) {
	for _, rule := range cfg.Rules {
		log.Printf("[rule %s] %s://%s", rule.Label, rule.Listen.Scheme, rule.Listen.Addr)
		if rule.Listen.Target != "" {
			log.Printf("[rule %s] forward target: %s", rule.Label, rule.Listen.Target)
		}
		logForwardChain(rule)
	}
	logIdleTimeout(cfg.Timeout)
}

// logForwardChain prints the hop order once at startup, because "nearest hop
// first" is easy to get backwards on the command line. Credentials are never
// logged.
func logForwardChain(rule config.Rule) {
	if len(rule.Upstream) == 0 {
		return
	}

	hops := make([]string, 0, len(rule.Upstream))
	for i, hop := range rule.Upstream {
		hops = append(hops, fmt.Sprintf("[%d] %s://%s", i, hop.Scheme, hop.Addr))
	}
	log.Printf("[rule %s] forward chain: %s -> target", rule.Label, strings.Join(hops, " -> "))
}

// logIdleTimeout prints the effective tunnel idle timeout so the running
// configuration can be confirmed from the log. Zero is reported as "disabled"
// rather than "0s" to avoid misreading it as an instantaneous timeout.
func logIdleTimeout(timeout time.Duration) {
	if timeout <= 0 {
		log.Println("tunnel idle timeout: disabled")
		return
	}
	log.Printf("tunnel idle timeout: %s", timeout)
}
