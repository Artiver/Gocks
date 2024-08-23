package utils

import (
	"Gocks/global"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

func ParseUrl(str string, arg *global.Url) error {
	u, err := url.Parse(str)
	if err != nil {
		return err
	}
	username := u.User.Username()
	password, _ := u.User.Password()
	password, err = url.QueryUnescape(password)
	if err != nil {
		return err
	}
	host := u.Host
	if strings.Contains(host, ".") && !strings.Contains(host, ":") {
		host += ":80"
	}
	arg.Scheme = u.Scheme
	arg.BindAddr = host
	arg.HttpAuthHeader = http.Header{}
	arg.HttpAuthHeader.Set(global.ProxyConnectKey, global.ProxyConnectValue)
	if username != "" && password != "" {
		arg.Socks5Auth = []byte{0x01}
		arg.Socks5Auth = append(arg.Socks5Auth, byte(len(username)))
		arg.Socks5Auth = append(arg.Socks5Auth, username...)
		arg.Socks5Auth = append(arg.Socks5Auth, byte(len(password)))
		arg.Socks5Auth = append(arg.Socks5Auth, password...)
		arg.HttpAuthHeader.Set(global.BasicAuthHeader, global.BasicAuthPrefix+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
		arg.Username = username
		arg.Password = password
	} else {
		arg.Socks5Auth = nil
	}
	return nil
}
