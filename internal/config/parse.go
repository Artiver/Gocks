package config

import (
	"encoding/base64"
	"fmt"
	"gocks/internal/constant"
	"net/http"
	"net/url"
	"strings"
)

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
	arg.HttpAuthHeader = http.Header{}
	arg.HttpAuthHeader.Set(constant.ProxyConnectKey, constant.ProxyConnectValue)
	if username != "" {
		// RFC 1929 limits both fields to 255 bytes.
		if len(username) > 255 || len(password) > 255 {
			return fmt.Errorf("username and password must be at most 255 bytes")
		}
		arg.Username = username
		arg.Password = password
		arg.AuthEnabled = true
		arg.HttpAuthHeader.Set(constant.BasicAuthHeader, constant.BasicAuthPrefix+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	} else {
		arg.AuthEnabled = false
	}
	arg.TranAddr = strings.TrimPrefix(u.Path, "/")
	return nil
}
