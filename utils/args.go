package utils

import (
	"strings"
)

type Configure struct {
	Username    string
	Password    string
	BindAddress string
}

var Server string
var Config Configure
var AuthRequired bool

const ProxySocks5 = "socks5"
const ProxyHTTP = "http"
const ProxyMix = "mix"

func SetBaseInfo(bindAddress, username, password string) {
	Config = Configure{
		Username:    username,
		Password:    password,
		BindAddress: bindAddress,
	}

	if Config.Username != "" && Config.Password != "" {
		AuthRequired = true
	} else {
		AuthRequired = false
	}

	if strings.HasPrefix(bindAddress, ProxySocks5) {
		Server = ProxySocks5
	} else if strings.HasPrefix(bindAddress, ProxyHTTP) {
		Server = ProxyHTTP
	} else {
		Server = ProxyMix
	}
}
