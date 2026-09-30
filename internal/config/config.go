package config

import (
	"encoding/base64"

	"gocks/internal/constant"
)

// Auth is the credential pair configured for one endpoint. A nil *Auth means
// the endpoint does not authenticate.
type Auth struct {
	Username string
	Password string
}

// ProxyAuthorization returns the value of the Proxy-Authorization header that
// carries these credentials (RFC 7617).
func (a *Auth) ProxyAuthorization() string {
	if a == nil {
		return ""
	}
	return constant.BasicAuthPrefix + base64.StdEncoding.EncodeToString([]byte(a.Username+":"+a.Password))
}

// Url describes one endpoint: the local listener (ProxyConfig) or a single
// upstream hop (ForwardChain).
type Url struct {
	Scheme   string
	BindAddr string
	// TranAddr is the forward target of the port-forwarding modes and is empty
	// for the proxy modes.
	TranAddr string
	// Auth is nil when the endpoint was configured without credentials.
	Auth *Auth
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

var AuthRequiredResponse = []byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Provide Auth Info\"\r\nConnection: close\r\n\r\n")
var ConnectedResponse = []byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: gocks\r\n\r\n")
var BadGatewayResponse = []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
