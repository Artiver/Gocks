package utils

import (
	"Gocks/global"
	"log"
	"strings"
)

func ParseArgsInfo(proxyAddr, forwardAddr string) {
	if strings.HasPrefix(proxyAddr, ":") {
		proxyAddr = "mix://" + proxyAddr
	}

	if err := ParseUrl(proxyAddr, &global.ProxyConfig); err != nil {
		log.Fatalln(err)
	}

	if err := ParseUrl(forwardAddr, &global.ForwardConfig); err != nil {
		log.Fatalln(err)
	}

	if global.ForwardConfig.BindAddr != "" {
		global.ForwardRequired = true
	} else {
		global.ForwardRequired = false
	}
}
