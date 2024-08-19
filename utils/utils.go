package utils

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
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

const Socks5HandleBytes = 256
const DefaultReadBytes = 512
const TcpConnectTimeout = 5 * time.Second

func FormatAddress(ip string, port uint16) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	} else {
		return fmt.Sprintf("%s:%d", ip, port)
	}
}

func TransportData(source, target *net.Conn) error {
	errChan := make(chan error, 1)

	go func() {
		_, err := io.Copy(*source, *target)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(*target, *source)
		errChan <- err
	}()

	err := <-errChan
	if err != nil && err == io.EOF {
		err = nil
	}
	return err
}

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
