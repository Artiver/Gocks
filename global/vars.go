package global

import (
	"net/http"
)

type AuthInfo struct {
	Username, Password string
}

type Url struct {
	Scheme        string
	BindAddr      string
	Socks5Auth    *AuthInfo
	HttpBasicAuth http.Header
}

var ProxyConfig Url
var ForwardConfig Url
var ForwardRequired bool

var CRLF = []byte("\r\n")
var AuthRequiredResponse = []byte("HTTP/1.1 407 ProxyConfig Authentication Required\r\nProxyConfig-Authenticate: Basic realm=\"ProxyConfig\"\r\n\r\n")
var ConnectedResponse = []byte("HTTP/1.1 200 Connection established\r\n\r\n")
