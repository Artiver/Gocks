package global

import (
	"golang.org/x/net/proxy"
	"net/http"
)

type Url struct {
	Scheme        string
	BindAddr      string
	Socks5Auth    *proxy.Auth
	HttpBasicAuth http.Header
}

var ProxyConfig Url
var ForwardConfig Url
var ForwardRequired bool

var CRLF = []byte("\r\n")
var AuthRequiredResponse = []byte("HTTP/1.1 407 ProxyConfig Authentication Required\r\nProxyConfig-Authenticate: Basic realm=\"ProxyConfig\"\r\n\r\n")
var ConnectedResponse = []byte("HTTP/1.1 200 Connection established\r\n\r\n")
