package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// defaultPort is added to an endpoint address that carries no port. It is not
// scheme aware: pass the port explicitly for anything but plain HTTP.
const defaultPort = "80"

// ParseUrl fills arg from an endpoint URL of the form
// scheme://[user:pass@]host[:port][/forward-target].
func ParseUrl(str string, arg *Url) error {
	u, err := url.Parse(str)
	if err != nil {
		return err
	}

	host, err := hostWithPort(u.Host)
	if err != nil {
		return err
	}

	arg.Scheme = u.Scheme
	arg.BindAddr = host
	arg.TranAddr = strings.TrimPrefix(u.Path, "/")
	arg.Auth = nil

	username := u.User.Username()
	password, _ := u.User.Password()
	if password, err = url.QueryUnescape(password); err != nil {
		return err
	}
	if username == "" {
		return nil
	}
	// RFC 1929 limits both fields to 255 bytes.
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("username and password must be at most 255 bytes")
	}
	arg.Auth = &Auth{Username: username, Password: password}
	return nil
}

// hostWithPort returns host with defaultPort added when it does not already
// carry a port. Bare IPv6 literals are bracketed so the result stays dialable.
func hostWithPort(host string) (string, error) {
	if host == "" {
		return "", nil
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host, nil
	}

	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return net.JoinHostPort(ip.String(), defaultPort), nil
	}
	if !strings.Contains(host, ":") {
		return host + ":" + defaultPort, nil
	}
	return "", fmt.Errorf("invalid address %q", host)
}
