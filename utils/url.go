package utils

import (
	"encoding/base64"
	"golang.org/x/net/proxy"
	"net/http"
	"net/url"
	"strings"
)

type Url struct {
	Scheme        string
	BindAddr      string
	Socks5Auth    *proxy.Auth
	HttpBasicAuth http.Header
}

func ParseUrl(str string, arg *Url) error {
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
	arg.HttpBasicAuth = http.Header{}
	arg.HttpBasicAuth.Set("Proxy-Connection", "keep-alive")
	if username != "" && password != "" {
		arg.Socks5Auth = &proxy.Auth{
			User:     username,
			Password: password,
		}
		arg.HttpBasicAuth.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	} else {
		arg.Socks5Auth = nil
	}
	return nil
}
