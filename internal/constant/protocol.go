package constant

import (
	"time"
)

// Endpoint schemes accepted by -L and -F.
const TCP = "tcp"
const UDP = "udp"
const HTTP = "http"
const Socks5 = "socks5"

const ConnectMethod = "CONNECT"

// DefaultReadBytes is the prefix the mixed-mode dispatcher reads to tell HTTP
// and SOCKS5 apart.
const DefaultReadBytes = 512

const TcpConnectTimeout = 5 * time.Second
const UdpReceiveTimeout = 3 * time.Second

// HandshakeTimeout bounds every protocol negotiation step, including the wait
// for a client's opening message.
const HandshakeTimeout = 10 * time.Second

// IdleTimeout bounds how long a tunnel may make no progress on either
// direction. The deadline is tracked across both halves of the connection:
// any data flowing one way refreshes the timer for the whole tunnel, so an
// asymmetric flow like a large download (silent client->target half) is not
// cut off while bytes are still arriving on the other half. Only when neither
// side moves for the full window is the tunnel closed.
var IdleTimeout = 300 * time.Second

// AcceptBackoff is the pause before retrying a failed Accept/ReadFrom.
const AcceptBackoff = 1 * time.Second

const BasicAuthHeader = "Proxy-Authorization"
const BasicAuthPrefix = "Basic "

const ProxyConnectKey = "Proxy-Connection"
const ProxyConnectValue = "keep-alive"

const ViaHeader = "Via"
const ViaValue = "1.1 gocks"
