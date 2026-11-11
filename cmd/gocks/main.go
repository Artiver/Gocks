package main

import (
	"context"
	"flag"
	"fmt"
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/proxy/http"
	"gocks/internal/proxy/mix"
	"gocks/internal/proxy/socks5"
	"gocks/internal/transport/tcp"
	"gocks/internal/transport/udp"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	proxyAddr     string
	upstreamAddrs config.UpstreamList
	idleTimeout   time.Duration
)

func main() {
	flag.StringVar(&proxyAddr, "L", ":8181", "Listen address (scheme://[user:pass@]host[:port][/target])")
	flag.Var(&upstreamAddrs, "F", "Upstream proxy address (repeatable, or a comma-separated list; nearest hop first)")
	flag.DurationVar(&idleTimeout, "timeout", 0, "Tunnel idle timeout (e.g. 30s, 5m); 0 disables it")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Lmicroseconds)

	cfg, err := config.Load(proxyAddr, upstreamAddrs, idleTimeout)
	if err != nil {
		log.Fatalln(err)
	}
	logStartup(cfg)

	// Shut down cleanly on Ctrl+C / SIGTERM by cancelling the run context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cfg.Listen.Scheme {
	case constant.Socks5:
		err = socks5.Run(ctx, cfg)
	case constant.HTTP:
		err = http.Run(ctx, cfg)
	case constant.TCP:
		err = tcp.Run(ctx, cfg)
	case constant.UDP:
		err = udp.Run(ctx, cfg)
	default:
		err = mix.Run(ctx, cfg)
	}
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("shutdown complete")
}

func logStartup(cfg config.Config) {
	logForwardChain(cfg.Upstream)
	logIdleTimeout(cfg.Timeout)
}

// logForwardChain prints the hop order once at startup, because "nearest hop
// first" is easy to get backwards on the command line. Credentials are never
// logged.
func logForwardChain(upstream []config.Endpoint) {
	if len(upstream) == 0 {
		return
	}

	hops := make([]string, 0, len(upstream))
	for i, hop := range upstream {
		hops = append(hops, fmt.Sprintf("[%d] %s://%s", i, hop.Scheme, hop.Addr))
	}
	log.Printf("forward chain: %s -> target", strings.Join(hops, " -> "))
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
