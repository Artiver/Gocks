package forward

import (
	"bufio"
	"errors"
	"gocks/internal/config"
	"gocks/internal/constant"
	"net"
	"net/http"
	"net/url"
	"time"
)

// dialHTTPHop sends a CONNECT request to the HTTP proxy hop over the already
// established conn, using that hop's own credentials.
func dialHTTPHop(conn net.Conn, hop config.Url, address string) error {
	if err := conn.SetDeadline(time.Now().Add(constant.HandshakeTimeout)); err != nil {
		return err
	}

	header := http.Header{}
	header.Set(constant.ProxyConnectKey, constant.ProxyConnectValue)
	if hop.Auth != nil {
		header.Set(constant.BasicAuthHeader, hop.Auth.ProxyAuthorization())
	}

	req := &http.Request{
		Method: constant.ConnectMethod,
		URL:    &url.URL{Host: address},
		Host:   address,
		Header: header,
	}
	if err := req.Write(conn); err != nil {
		return err
	}

	// A proxy answers CONNECT with headers only, and the next hop waits for
	// our next write, so nothing can be buffered past the response here.
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	return conn.SetDeadline(time.Time{})
}
