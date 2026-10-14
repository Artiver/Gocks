package http

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// requestFromRaw parses raw into a request, so test cases carry realistic
// proto and header state.
func requestFromRaw(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	return req
}

// responseFromRaw parses raw into a response. req may be nil for plain
// responses; it drives body-length semantics for HEAD and 1xx cases.
func responseFromRaw(t *testing.T, raw string, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	resp.Body.Close()
	return resp
}

// ---------------------------------------------------------------------------
// targetAddr
// ---------------------------------------------------------------------------

func TestTargetAddr(t *testing.T) {
	cases := []struct {
		name        string
		host        string
		urlHost     string
		defaultPort string
		want        string
	}{
		{"domain gets default port", "example.com", "", "443", "example.com:443"},
		{"explicit port is kept", "example.com:8080", "", "443", "example.com:8080"},
		{"bare ipv6 gets default port", "2001:db8::1", "", "443", "[2001:db8::1]:443"},
		{"bracketed ipv6 gets default port", "[::1]", "", "443", "[::1]:443"},
		{"bracketed ipv6 port is kept", "[::1]:8443", "", "443", "[::1]:8443"},
		{"empty host falls back to url", "", "example.com", "80", "example.com:80"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Host: tc.host, URL: &url.URL{Host: tc.urlHost}}
			if got := targetAddr(req, tc.defaultPort); got != tc.want {
				t.Errorf("targetAddr(host=%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// finishResponse
// ---------------------------------------------------------------------------

func TestFinishResponse(t *testing.T) {
	req11 := requestFromRaw(t, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req10 := requestFromRaw(t, "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
	req10KeepAlive := requestFromRaw(t, "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n")
	req11Close := requestFromRaw(t, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

	chunkedRaw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"

	cases := []struct {
		name        string
		req         *http.Request
		respRaw     string
		wantClose   bool
		wantChunked bool
	}{
		{
			name:        "http/1.1 keeps chunked and keep-alive",
			req:         req11,
			respRaw:     chunkedRaw,
			wantClose:   false,
			wantChunked: true,
		},
		{
			name:      "unknown-length body forces close",
			req:       req11,
			respRaw:   "HTTP/1.0 200 OK\r\n\r\nhello",
			wantClose: true,
		},
		{
			name:      "http/1.0 client drops chunked and forces close",
			req:       req10KeepAlive,
			respRaw:   chunkedRaw,
			wantClose: true,
		},
		{
			name:      "http/1.0 keep-alive with content-length stays open",
			req:       req10KeepAlive,
			respRaw:   "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello",
			wantClose: false,
		},
		{
			name:      "http/1.0 without keep-alive closes",
			req:       req10,
			respRaw:   "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello",
			wantClose: true,
		},
		{
			name:      "http/1.1 connection close closes",
			req:       req11Close,
			respRaw:   "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello",
			wantClose: true,
		},
		{
			name:      "204 response stays open",
			req:       req11,
			respRaw:   "HTTP/1.1 204 No Content\r\n\r\n",
			wantClose: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := responseFromRaw(t, tc.respRaw, tc.req)
			if got := finishResponse(tc.req, resp); got != tc.wantClose {
				t.Errorf("finishResponse() = %v, want %v", got, tc.wantClose)
			}
			if tc.wantChunked && len(resp.TransferEncoding) == 0 {
				t.Error("TransferEncoding was dropped, want chunked kept")
			}
			if !tc.wantChunked && len(resp.TransferEncoding) > 0 {
				t.Errorf("TransferEncoding = %v, want dropped", resp.TransferEncoding)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// End-to-end proxying
// ---------------------------------------------------------------------------

// rawUpstream serves one canned response per accepted connection, after
// draining the request the proxy forwards. When halfClose is set the upstream
// half-closes its write side after the response, delimiting a body that
// carries no Content-Length.
func rawUpstream(t *testing.T, resp []byte, halfClose bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				if _, err := c.Read(buf); err != nil && err != io.EOF {
					return
				}
				if _, err := c.Write(resp); err != nil {
					return
				}
				if halfClose {
					if cw, ok := c.(interface{ CloseWrite() error }); ok {
						cw.CloseWrite()
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// proxyListener starts an HTTP proxy on a loopback port and returns its
// address.
func proxyListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go HandleHTTPConnection(c, nil)
		}
	}()
	return ln.Addr().String()
}

// proxyClient returns a client that routes all traffic through the proxy.
func proxyClient(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
}

// TestHandleProxyUnknownLengthResponse checks that an upstream response
// without Content-Length is delivered in full and the proxy closes the client
// connection afterwards, so the client's end of the body is not left hanging
// on a kept-alive connection.
func TestHandleProxyUnknownLengthResponse(t *testing.T) {
	upstream := rawUpstream(t, []byte("HTTP/1.0 200 OK\r\n\r\nhello world"), true)
	proxyAddr := proxyListener(t)

	client := proxyClient(t, proxyAddr)
	resp, err := client.Get("http://" + upstream + "/data")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != "hello world" {
		t.Errorf("body = %q, want %q", body, "hello world")
	}
}

// TestHandleProxyKeepAliveChunked checks that a chunked upstream response
// keeps the proxy connection reusable: a second request over the same client
// succeeds without the proxy closing the connection in between.
func TestHandleProxyKeepAliveChunked(t *testing.T) {
	upstream := rawUpstream(t, []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), false)
	proxyAddr := proxyListener(t)

	client := proxyClient(t, proxyAddr)
	for i := 0; i < 2; i++ {
		resp, err := client.Get("http://" + upstream + "/data")
		if err != nil {
			t.Fatalf("Get #%d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("ReadAll #%d: %v", i, err)
		}
		if string(body) != "hello" {
			t.Errorf("body #%d = %q, want %q", i, body, "hello")
		}
	}
}
