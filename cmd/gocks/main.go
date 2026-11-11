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

var proxyAddr string
var forwardAddrs config.ForwardList
var idleTimeout time.Duration

func init() {
	flag.StringVar(&proxyAddr, "L", ":8181", "ProxyConfig Listen Address")
	flag.Var(&forwardAddrs, "F", "Upstream proxy address (repeatable, or a comma-separated list; nearest hop first)")
	flag.DurationVar(&idleTimeout, "timeout", 0, "Tunnel idle timeout (e.g. 30s, 5m); 0 disables it")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Lmicroseconds)
}

func main() {
	config.ParseArgsInfo(proxyAddr, forwardAddrs, idleTimeout)
	logForwardChain()
	logIdleTimeout()

	// Shut down cleanly on Ctrl+C / SIGTERM by cancelling the run context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch config.ProxyConfig.Scheme {
	case constant.Socks5:
		err = socks5.Run(ctx)
	case constant.HTTP:
		err = http.Run(ctx)
	case constant.TCP:
		err = tcp.Run(ctx)
	case constant.UDP:
		err = udp.Run(ctx)
	default:
		err = mix.Run(ctx)
	}
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("shutdown complete")
}

// logForwardChain prints the hop order once at startup, because "nearest hop
// first" is easy to get backwards on the command line. Credentials are never
// logged.
func logForwardChain() {
	if len(config.ForwardChain) == 0 {
		return
	}

	hops := make([]string, 0, len(config.ForwardChain))
	for i, hop := range config.ForwardChain {
		hops = append(hops, fmt.Sprintf("[%d] %s://%s", i, hop.Scheme, hop.BindAddr))
	}
	log.Printf("forward chain: %s -> target", strings.Join(hops, " -> "))
}

// logIdleTimeout prints the effective tunnel idle timeout so the running
// configuration can be confirmed from the log. Zero is reported as "disabled"
// rather than "0s" to avoid misreading it as an instantaneous timeout.
func logIdleTimeout() {
	if constant.TunnelIdleTimeout <= 0 {
		log.Println("tunnel idle timeout: disabled")
		return
	}
	log.Printf("tunnel idle timeout: %s", constant.TunnelIdleTimeout)
}
