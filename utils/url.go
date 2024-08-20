package utils

import (
	"golang.org/x/net/proxy"
	"net/url"
	"strings"
)

type Url struct {
	Scheme   string
	BindAddr string
	Auth     *proxy.Auth
}

func ParseUrl(str string, arg *Url) error {
	u, err := url.Parse(str)
	if err != nil {
		return err
	}
	username := u.User.Username()
	password, _ := u.User.Password()
	host := u.Host
	if strings.Contains(host, ".") && !strings.Contains(host, ":") {
		host += ":80"
	}
	arg.Scheme = u.Scheme
	arg.BindAddr = host
	if username != "" && password != "" {
		arg.Auth = &proxy.Auth{
			User:     username,
			Password: password,
		}
	} else {
		arg.Auth = nil
	}
	return nil
}
