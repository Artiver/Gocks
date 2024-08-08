package main

import (
	"Gocks/http"
	"Gocks/mix"
	"Gocks/socks5"
	"Gocks/utils"
	"flag"
	"log"
)

var Server string
var Username string
var Password string
var Host string
var Port uint

func init() {
	flag.StringVar(&Server, "type", "socks5", "server type, [socks5, http]")
	flag.StringVar(&Username, "user", "", "Username for proxy auth")
	flag.StringVar(&Password, "pass", "", "Password for proxy auth")
	flag.StringVar(&Host, "host", "", "Host for proxy")
	flag.UintVar(&Port, "port", 8181, "Port for proxy")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Lmicroseconds)
}

func main() {
	utils.SetBaseInfo(Host, uint16(Port), Username, Password)
	switch Server {
	case "socks5":
		socks5.Run()
	case "http":
		http.Run()
	case "mix":
		mix.Run()
	}
}
