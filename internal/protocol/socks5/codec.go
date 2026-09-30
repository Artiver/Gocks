// Package socks5 implements the SOCKS5 protocol (RFC 1928) and the
// username/password authentication sub-negotiation (RFC 1929).
//
// It is a self-contained codec. Every message is framed by its exact wire
// length using io.ReadFull, so callers may decode from a buffered or
// prefixed reader without losing bytes that follow the message.
package socks5

import "errors"

// Protocol versions.
const (
	// Version is the SOCKS5 protocol version.
	Version byte = 0x05
	// UserPassVersion is the version of the username/password
	// authentication sub-negotiation.
	UserPassVersion byte = 0x01
)

// Authentication methods (RFC 1928 §3).
const (
	MethodNoAuth       byte = 0x00
	MethodGSSAPI       byte = 0x01
	MethodUserPass     byte = 0x02
	MethodNoAcceptable byte = 0xFF
)

// Commands (RFC 1928 §4).
const (
	CmdConnect byte = 0x01
	CmdBind    byte = 0x02
	CmdUDP     byte = 0x03
)

// Address types (RFC 1928 §4).
const (
	AddrIPv4   byte = 0x01
	AddrDomain byte = 0x03
	AddrIPv6   byte = 0x04
)

// Reply codes (RFC 1928 §6).
const (
	RepSucceeded       byte = 0x00
	RepFailure         byte = 0x01
	RepNotAllowed      byte = 0x02
	RepNetUnreachable  byte = 0x03
	RepHostUnreachable byte = 0x04
	RepConnRefused     byte = 0x05
	RepTTLExpired      byte = 0x06
	RepCmdUnsupported  byte = 0x07
	RepAddrUnsupported byte = 0x08
)

// Username/password authentication status codes (RFC 1929).
const (
	UserPassSuccess byte = 0x00
	UserPassFailure byte = 0x01
)

// Codec errors.
var (
	ErrBadVersion  = errors.New("socks5: bad version")
	ErrBadFormat   = errors.New("socks5: bad format")
	ErrBadAddrType = errors.New("socks5: bad address type")
	ErrBadMethod   = errors.New("socks5: bad method")
	ErrAuthFailure = errors.New("socks5: authentication failure")
)

// ReprString returns a human readable description of a reply code.
func ReprString(rep byte) string {
	switch rep {
	case RepSucceeded:
		return "succeeded"
	case RepFailure:
		return "general failure"
	case RepNotAllowed:
		return "not allowed"
	case RepNetUnreachable:
		return "network unreachable"
	case RepHostUnreachable:
		return "host unreachable"
	case RepConnRefused:
		return "connection refused"
	case RepTTLExpired:
		return "TTL expired"
	case RepCmdUnsupported:
		return "command not supported"
	case RepAddrUnsupported:
		return "address type not supported"
	default:
		return "unknown"
	}
}
