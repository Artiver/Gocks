package main

import (
	"Gocks/http"
	"Gocks/mix"
	"Gocks/socks5"
	"Gocks/utils"
	"flag"
	"log"
)

var Username string
var Password string
var ListenAddress string
var ForwardAddress string

func init() {
	flag.StringVar(&ListenAddress, "L", ":8181", "Proxy Listen Address")
	flag.StringVar(&ForwardAddress, "F", "", "Proxy ForwardConfig Address")
	flag.StringVar(&Username, "u", "", "Username for proxy auth")
	flag.StringVar(&Password, "p", "", "Password for proxy auth")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Lmicroseconds)
}

func main() {
	utils.SetBaseInfo(ListenAddress, ForwardAddress, Username, Password)
	switch utils.Server {
	case utils.ProxySocks5:
		socks5.Run()
	case utils.ProxyHTTP:
		http.Run()
	case utils.ProxyMix:
		mix.Run()
	}
}
