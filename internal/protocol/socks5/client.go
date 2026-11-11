package socks5

import (
	"errors"
	"fmt"
	"io"
)

// ClientHandshake negotiates the authentication method with a SOCKS5 proxy and
// completes the method-specific sub-negotiation. auth is nil when no
// credentials are configured, in which case only no-auth is offered.
func ClientHandshake(conn io.ReadWriter, auth *Credential) error {
	methods := []byte{MethodNoAuth}
	if auth != nil {
		methods = append(methods, MethodUserPass)
	}

	greeting := make([]byte, 0, 2+len(methods))
	greeting = append(greeting, Version, byte(len(methods)))
	greeting = append(greeting, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return err
	}

	var selected [2]byte
	if _, err := io.ReadFull(conn, selected[:]); err != nil {
		return err
	}
	if selected[0] != Version {
		return ErrBadVersion
	}

	switch selected[1] {
	case MethodNoAuth:
		return nil

	case MethodUserPass:
		if auth == nil {
			return errors.New("socks5: upstream requires authentication but none is configured")
		}
		req := NewUserPassRequest(UserPassVersion, auth.Username, auth.Password)
		if err := req.Write(conn); err != nil {
			return err
		}
		resp, err := ReadUserPassResponse(conn)
		if err != nil {
			return err
		}
		if resp.Status != UserPassSuccess {
			return ErrAuthFailure
		}
		return nil

	case MethodNoAcceptable:
		return ErrBadMethod

	default:
		return fmt.Errorf("socks5: upstream selected unsupported method %d", selected[1])
	}
}
