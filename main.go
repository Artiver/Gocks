package main

import (
	"Gocks/http"
	"Gocks/mix"
	"Gocks/socks5"
	"Gocks/utils"
	"flag"
	"log"
)

func init() {
	flag.StringVar(&(utils.Config.BindAddr), "L", ":8181", "Proxy Listen Address")
	flag.StringVar(&(utils.Forward.BindAddr), "F", "", "Proxy ForwardConfig Address")
	flag.StringVar(&(utils.Config.Username), "u", "", "Username for proxy auth")
	flag.StringVar(&(utils.Config.Password), "p", "", "Password for proxy auth")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Lmicroseconds)
}

func main() {
	utils.SetBaseInfo()
	switch utils.Server {
	case utils.ProxySocks5:
		socks5.Run()
	case utils.ProxyHTTP:
		http.Run()
	case utils.ProxyMix:
		mix.Run()
	}
}
