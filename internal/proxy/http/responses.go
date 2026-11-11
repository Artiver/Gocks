package http

const (
	authRequiredResponse = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Provide Auth Info\"\r\nConnection: close\r\n\r\n"
	connectedResponse    = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: gocks\r\n\r\n"
	badGatewayResponse   = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)
