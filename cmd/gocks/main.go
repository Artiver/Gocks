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
)

var proxyAddr string
var forwardAddrs config.ForwardList

func init() {
	flag.StringVar(&proxyAddr, "L", ":8181", "ProxyConfig Listen Address")
	flag.Var(&forwardAddrs, "F", "Upstream proxy address (repeatable, or a comma-separated list; nearest hop first)")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Lmicroseconds)
}

func main() {
	config.ParseArgsInfo(proxyAddr, forwardAddrs)
	logForwardChain()

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
