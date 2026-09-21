package main

import (
	"flag"
	"gocks/internal/config"
	"gocks/internal/constant"
	"gocks/internal/proxy/http"
	"gocks/internal/proxy/mix"
	"gocks/internal/proxy/socks5"
	"gocks/internal/transport/tcp"
	"gocks/internal/transport/udp"
	"log"
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
	switch config.ProxyConfig.Scheme {
	case constant.Socks5:
		socks5.Run()
	case constant.HTTP:
		http.Run()
	case constant.TCP:
		tcp.Run()
	case constant.UDP:
		udp.Run()
	default:
		mix.Run()
	}
}
