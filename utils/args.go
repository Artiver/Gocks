package utils

import (
	"strings"
)

type ForwardConfig struct {
	Username string
	Password string
	BindAddr string
}

type BindConfig struct {
	Username string
	Password string
	BindAddr string
}

var Server string
var Config BindConfig
var Forward ForwardConfig
var AuthRequired bool
var ForwardRequired bool

const ProxySocks5 = "socks5"
const ProxyHTTP = "http"
const ProxyMix = "mix"

func SetBaseInfo(bindAddr, forwardAddr, username, password string) {
	Config = BindConfig{
		Username: username,
		Password: password,
		BindAddr: bindAddr,
	}

	Forward = ForwardConfig{
		BindAddr: forwardAddr,
	}

	if Config.Username != "" && Config.Password != "" {
		AuthRequired = true
	} else {
		AuthRequired = false
	}

	if Forward.BindAddr != "" {
		ForwardRequired = true
	} else {
		ForwardRequired = false
	}

	if strings.HasPrefix(bindAddr, ProxySocks5) {
		Server = ProxySocks5
	} else if strings.HasPrefix(bindAddr, ProxyHTTP) {
		Server = ProxyHTTP
	} else {
		Server = ProxyMix
	}
}
