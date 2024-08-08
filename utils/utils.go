package utils

import (
	"fmt"
	"strings"
)

type Configure struct {
	Username      string
	Password      string
	IpAddress     string
	Port          uint16
	CombineIpPort string
}

var Config Configure
var AuthRequired bool

func FormatAddress(ip string, port uint16) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	} else {
		return fmt.Sprintf("%s:%d", ip, port)
	}
}

func SetBaseInfo(ip string, port uint16, username, password string) {
	Config = Configure{
		Username:      username,
		Password:      password,
		IpAddress:     ip,
		Port:          port,
		CombineIpPort: FormatAddress(ip, port),
	}

	if Config.Username != "" && Config.Password != "" {
		AuthRequired = true
	} else {
		AuthRequired = false
	}
}
