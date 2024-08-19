package utils

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
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
