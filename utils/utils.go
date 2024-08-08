package utils

import (
	"fmt"
	"strings"
)

type Config struct {
	Username  string
	Password  string
	IpAddress string
	Port      uint16
}

func FormatAddress(ip string, port uint16) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	} else {
		return fmt.Sprintf("%s:%d", ip, port)
	}
}
