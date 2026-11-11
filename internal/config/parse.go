package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// defaultPort is added to an endpoint address that carries no port. It is not
// scheme aware: pass the port explicitly for anything but plain HTTP.
const defaultPort = "80"

// ParseEndpoint fills arg from an endpoint URL of the form
// scheme://[user:pass@]host[:port][/forward-target].
func ParseEndpoint(str string, arg *Endpoint) error {
	u, err := url.Parse(str)
	if err != nil {
		return err
	}

	host, err := hostWithPort(u.Host)
	if err != nil {
		return err
	}

	arg.Scheme = u.Scheme
	arg.Addr = host
	arg.Target = strings.TrimPrefix(u.Path, "/")
	arg.Auth = nil

	username := u.User.Username()
	password, _ := u.User.Password()
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
	if _, port, err := net.SplitHostPort(host); err == nil {
		if err := validatePort(port); err != nil {
			return "", err
		}
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

// validatePort rejects numeric ports outside the 16-bit range. Service names
// are left to net.Dial to resolve.
func validatePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil {
		return nil
	}
	if n < 0 || n > 65535 {
		return fmt.Errorf("port out of range: %d", n)
	}
	return nil
}
