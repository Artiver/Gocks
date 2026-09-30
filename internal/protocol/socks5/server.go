package socks5

import (
	"crypto/subtle"
	"io"
)

// Selector negotiates the authentication method for a server-side handshake.
type Selector interface {
	// Select picks the method to use from the methods offered by the client.
	// It returns MethodNoAcceptable when none is supported.
	Select(methods []byte) byte

	// OnSelected completes the sub-negotiation for the chosen method and
	// returns the authenticated client ID (empty when unauthenticated).
	OnSelected(method byte, conn io.ReadWriter) (clientID string, err error)
}

// ServerHandshake performs the SOCKS5 method negotiation followed by the
// method-specific sub-negotiation. It returns the authenticated client ID,
// which is empty when authentication is not used.
func ServerHandshake(conn io.ReadWriter, selector Selector) (string, error) {
	methods, err := ReadMethods(conn)
	if err != nil {
		return "", err
	}

	method := MethodNoAuth
	if selector != nil {
		method = selector.Select(methods)
	}

	if err := WriteMethod(method, conn); err != nil {
		return "", err
	}
	if method == MethodNoAcceptable {
		return "", ErrBadMethod
	}
	if selector == nil {
		return "", nil
	}
	return selector.OnSelected(method, conn)
}

// Credential is a username/password pair accepted by a ServerSelector.
type Credential struct {
	Username string
	Password string
}

// ServerSelector is a Selector supporting the no-authentication and
// username/password methods. When at least one Credential is configured,
// authentication is mandatory and the no-authentication method is refused.
type ServerSelector struct {
	users []Credential
}

// NewServerSelector returns a selector enforcing the given credentials.
func NewServerSelector(users ...Credential) *ServerSelector {
	return &ServerSelector{users: users}
}

// Select implements Selector.
func (s *ServerSelector) Select(methods []byte) byte {
	if len(s.users) > 0 {
		if HasMethod(methods, MethodUserPass) {
			return MethodUserPass
		}
		return MethodNoAcceptable
	}
	if HasMethod(methods, MethodNoAuth) {
		return MethodNoAuth
	}
	return MethodNoAcceptable
}

// OnSelected implements Selector.
func (s *ServerSelector) OnSelected(method byte, conn io.ReadWriter) (string, error) {
	switch method {
	case MethodNoAuth:
		return "", nil

	case MethodUserPass:
		req, err := ReadUserPassRequest(conn)
		if err != nil {
			return "", err
		}
		if !s.authenticate(req.Username, req.Password) {
			// Best effort: the connection is closed by the caller anyway.
			NewUserPassResponse(UserPassVersion, UserPassFailure).Write(conn)
			return "", ErrAuthFailure
		}
		if err := NewUserPassResponse(UserPassVersion, UserPassSuccess).Write(conn); err != nil {
			return "", err
		}
		return req.Username, nil

	default:
		return "", ErrBadMethod
	}
}

func (s *ServerSelector) authenticate(username, password string) bool {
	for _, u := range s.users {
		userOK := subtle.ConstantTimeCompare([]byte(username), []byte(u.Username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(password), []byte(u.Password)) == 1
		if userOK && passOK {
			return true
		}
	}
	return false
}
