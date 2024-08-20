package main

import (
	"Gocks/http"
	"Gocks/mix"
	"Gocks/socks5"
	"Gocks/utils"
	"flag"
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
	utils.ParseArgsInfo(proxyAddr, forwardAddr)
	switch utils.ProxyConfig.Scheme {
	case utils.Socks5:
		socks5.Run()
	case utils.HTTP:
		http.Run()
	default:
		mix.Run()
	}
}
