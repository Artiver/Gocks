package http

import (
	"Gocks/global"
	"Gocks/utils"
	"bufio"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func startProxy(t *testing.T, auth bool) (string, func()) {
	if auth {
		global.ProxyConfig.Username = "testuser"
		global.ProxyConfig.Password = "testpass"
		global.ProxyConfig.Socks5Auth = []byte{0x01}
	} else {
		global.ProxyConfig.Socks5Auth = nil
	}
	global.ForwardRequired = false

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go HandleHTTPConnection(&conn, nil)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func dialThroughProxy(t *testing.T, proxyAddr, targetURL, proxyAuth string) (*http.Response, string) {
	u, err := url.Parse(targetURL)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	req := &http.Request{
		Method: "GET",
		URL:    u,
		Host:   u.Host,
		Header: make(http.Header),
	}
	req.Header.Set("Proxy-Connection", "keep-alive")
	if proxyAuth != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+proxyAuth)
	}

	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	conn.Close()
	return resp, string(body)
}

func TestProxyBasicHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "backend-ok: %s %s", r.Method, r.URL.Path)
	}))
	defer backend.Close()

	proxyAddr, stop := startProxy(t, false)
	defer stop()

	resp, body := dialThroughProxy(t, proxyAddr, backend.URL, "")
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "backend-ok") {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestProxyKeepAlive(t *testing.T) {
	requestCount := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		fmt.Fprintf(w, "req-%d", requestCount)
	}))
	defer backend.Close()

	proxyAddr, stop := startProxy(t, false)
	defer stop()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	u, _ := url.Parse(backend.URL)
	br := bufio.NewReader(conn)

	for i := 0; i < 3; i++ {
		req := &http.Request{
			Method:     "GET",
			URL:        u,
			Host:       u.Host,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		req.Header.Set("Proxy-Connection", "keep-alive")
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		expected := fmt.Sprintf("req-%d", i+1)
		if string(body) != expected {
			t.Fatalf("request %d: expected %s, got %s", i+1, expected, string(body))
		}
	}
}

func TestProxyConnectTunnel(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunnel-ok")
	}))
	defer backend.Close()

	proxyAddr, stop := startProxy(t, false)
	defer stop()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	target := strings.TrimPrefix(backend.URL, "http://")
	req := &http.Request{
		Method:     "CONNECT",
		URL:        &url.URL{Host: target},
		Host:       target,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	tunnelReq := "GET / HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(tunnelReq)); err != nil {
		t.Fatal(err)
	}

	tunnelResp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(tunnelResp.Body)
	tunnelResp.Body.Close()
	if !strings.Contains(string(body), "tunnel-ok") {
		t.Fatalf("unexpected tunnel body: %s", string(body))
	}
}

func TestProxyAuthRequired(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should-not-reach")
	}))
	defer backend.Close()

	proxyAddr, stop := startProxy(t, true)
	defer stop()

	resp, _ := dialThroughProxy(t, proxyAddr, backend.URL, "")
	if resp.StatusCode != 407 {
		t.Fatalf("expected 407, got %d", resp.StatusCode)
	}
}

func TestProxyAuthSuccess(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "auth-ok")
	}))
	defer backend.Close()

	proxyAddr, stop := startProxy(t, true)
	defer stop()

	encoded := "dGVzdHVzZXI6dGVzdHBhc3M="
	resp, body := dialThroughProxy(t, proxyAddr, backend.URL, encoded)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "auth-ok") {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestProxyAuthWrong(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should-not-reach")
	}))
	defer backend.Close()

	proxyAddr, stop := startProxy(t, true)
	defer stop()

	encoded := "d3Jvbmc6d3Jvbmc="
	resp, _ := dialThroughProxy(t, proxyAddr, backend.URL, encoded)
	if resp.StatusCode != 407 {
		t.Fatalf("expected 407, got %d", resp.StatusCode)
	}
}

func TestProxyStripsAuthHeader(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	proxyAddr, stop := startProxy(t, true)
	defer stop()

	encoded := "dGVzdHVzZXI6dGVzdHBhc3M="
	dialThroughProxy(t, proxyAddr, backend.URL, encoded)

	if pa := receivedHeaders.Get("Proxy-Authorization"); pa != "" {
		t.Fatalf("Proxy-Authorization should be stripped, got: %s", pa)
	}
	if pc := receivedHeaders.Get("Proxy-Connection"); pc != "" {
		t.Fatalf("Proxy-Connection should be stripped, got: %s", pc)
	}
}

func TestProxyAddsViaHeader(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	proxyAddr, stop := startProxy(t, false)
	defer stop()

	dialThroughProxy(t, proxyAddr, backend.URL, "")

	if via := receivedHeaders.Get("Via"); via == "" {
		t.Fatal("Via header should be present in forwarded request")
	}
}

func TestProxyBadGateway(t *testing.T) {
	proxyAddr, stop := startProxy(t, false)
	defer stop()

	resp, _ := dialThroughProxy(t, proxyAddr, "http://192.0.2.1:80/get", "")
	if resp.StatusCode != 502 {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := "secret"
	b := "secret"
	c := "wrong"
	if subtle.ConstantTimeCompare([]byte(a), []byte(b)) != 1 {
		t.Fatal("equal strings should match")
	}
	if subtle.ConstantTimeCompare([]byte(a), []byte(c)) == 1 {
		t.Fatal("different strings should not match")
	}
}

func TestTransportDataNoLeak(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	connA := a
	connB := b

	done := make(chan error, 1)
	go func() {
		done <- utils.TransportData(&connA, &connB)
	}()

	go func() {
		time.Sleep(100 * time.Millisecond)
		a.Write([]byte("hello"))
		a.Close()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("TransportData leaked goroutine: timed out")
	}
}
