package main

import (
	"context"
	"flag"
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
	"syscall"
)

var proxyAddr string
var forwardAddr string

func init() {
	flag.StringVar(&proxyAddr, "L", ":8181", "ProxyConfig Listen Address")
	flag.StringVar(&forwardAddr, "F", "", "ProxyConfig ForwardConfig Address")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Lmicroseconds)
}

func main() {
	config.ParseArgsInfo(proxyAddr, forwardAddr)

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
