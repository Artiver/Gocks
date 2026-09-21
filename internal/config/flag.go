package config

import (
	"log"
	"strings"
)

func ParseArgsInfo(proxyAddr, forwardAddr string) {
	if strings.HasPrefix(proxyAddr, ":") {
		proxyAddr = "mix://" + proxyAddr
	}

	if err := ParseUrl(proxyAddr, &ProxyConfig); err != nil {
		log.Fatalln(err)
	}

	if err := ParseUrl(forwardAddr, &ForwardConfig); err != nil {
		log.Fatalln(err)
	}

	if ForwardConfig.BindAddr != "" {
		ForwardRequired = true
	} else {
		ForwardRequired = false
	}
}
