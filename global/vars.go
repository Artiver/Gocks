package global

import (
	"net/http"
)

type AuthInfo struct {
	Username, Password string
}

type Url struct {
	Scheme   string
	BindAddr string
	AuthInfo
	Socks5Auth     []byte
	HttpAuthHeader http.Header
}

var ProxyConfig Url
var ForwardConfig Url
var ForwardRequired bool

var CRLF = []byte("\r\n")
var AuthRequiredResponse = []byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Provide Auth Info\"\r\n\r\n")
var ConnectedResponse = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
