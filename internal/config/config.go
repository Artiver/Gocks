package config

import (
	"net/http"
)

type AuthInfo struct {
	Username, Password string
}

type Url struct {
	Scheme   string
	BindAddr string
	TranAddr string
	AuthInfo
	// AuthEnabled reports whether credentials were configured for this endpoint.
	AuthEnabled    bool
	HttpAuthHeader http.Header
}

var ProxyConfig Url

// ForwardChain is the ordered list of upstream proxies a dial traverses: the
// first entry is contacted directly and the last one reaches the final target.
// One entry reproduces the classic single-level -F behaviour, an empty chain
// dials directly.
var ForwardChain []Url

// MaxForwardHops bounds the chain so a misconfigured command line cannot build
// an unbounded proxy chain.
const MaxForwardHops = 32

var CRLF = []byte("\r\n")
var AuthRequiredResponse = []byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Provide Auth Info\"\r\nConnection: close\r\n\r\n")
var ConnectedResponse = []byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: gocks\r\n\r\n")
var BadGatewayResponse = []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
var GatewayTimeoutResponse = []byte("HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
