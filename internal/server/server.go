// Package server holds the TCP accept loop shared by the proxies and the TCP
// port forwarder.
package server

import (
	"context"
	"gocks/internal/constant"
	"gocks/internal/netutil"
	"log"
	"net"
)

// Serve listens on addr and serves it until ctx is cancelled.
func Serve(ctx context.Context, label, addr string, handle func(net.Conn)) error {
	listen, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ServeListener(ctx, label, listen, handle)
}

// ServeListener accepts connections on listen until ctx is cancelled, handling
// each one in its own goroutine. A failed Accept is logged and retried after
// constant.AcceptBackoff instead of spinning, and cancelling ctx closes the
// listener so ServeListener returns nil rather than an accept error.
func ServeListener(ctx context.Context, label string, listen net.Listener, handle func(net.Conn)) error {
	defer listen.Close()

	go func() {
		<-ctx.Done()
		listen.Close()
	}()

	log.Println(label, "listening", listen.Addr())

	for {
		conn, err := listen.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Println("Error accepting connection:", err)
			if !netutil.Sleep(ctx, constant.AcceptBackoff) {
				return nil
			}
			continue
		}
		go handle(conn)
	}
}
