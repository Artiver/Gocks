package config

import (
	"encoding/base64"
	"io"
	"time"

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

// Endpoint describes one endpoint: the local listener of a rule or a single
// upstream hop.
type Endpoint struct {
	Scheme string
	Addr   string
	// Target is the forward target of the port-forwarding modes and is empty
	// for the proxy modes.
	Target string
	// Auth is nil when the endpoint was configured without credentials.
	Auth *Auth
}

// Rule is one independent listening rule: a local listener and the upstream
// chain that every connection it serves traverses.
type Rule struct {
	// Label identifies the rule in logs, e.g. "1/5".
	Label string
	// Listen is the local endpoint to serve.
	Listen Endpoint
	// Upstream is the ordered list of upstream proxies a dial traverses: the
	// first entry is contacted directly and the last one reaches the final
	// target. An empty list dials directly.
	Upstream []Endpoint
	// Timeout bounds how long a TCP tunnel may make no progress; zero disables
	// the idle timeout.
	Timeout time.Duration
	// LogOutput receives this rule's log lines. A nil writer means os.Stderr.
	// Startup injects a non-blocking sink so a stalled console cannot block
	// the connection handlers.
	LogOutput io.Writer
}

// Config is the runtime configuration derived from the command line.
type Config struct {
	// Rules is the ordered list of listeners to serve, one goroutine each.
	Rules []Rule
	// Timeout is the process-wide idle timeout, copied into every rule.
	Timeout time.Duration
}

// MaxUpstreamHops bounds the chain so a misconfigured command line cannot
// build an unbounded proxy chain.
const MaxUpstreamHops = 32

// MaxRules bounds how many listeners one process may serve.
const MaxRules = 64
