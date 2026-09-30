package http

import (
	"crypto/subtle"
	"encoding/base64"
	"gocks/internal/config"
	"gocks/internal/constant"
	"log"
	"net/http"
	"strings"
)

func checkProxyAuthorizationFromHeader(auth *config.Auth, header http.Header) bool {
	return checkAuthHeader(auth, header.Get(constant.BasicAuthHeader))
}

// checkAuthHeader verifies one Proxy-Authorization header value against auth.
// Both fields are compared in constant time so the response cannot be used as
// a timing oracle.
func checkAuthHeader(auth *config.Auth, authHeader string) bool {
	if auth == nil || !strings.HasPrefix(authHeader, constant.BasicAuthPrefix) {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, constant.BasicAuthPrefix))
	if err != nil {
		log.Println("failed to decode Proxy-Authorization header:", err)
		return false
	}

	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false
	}

	userMatch := subtle.ConstantTimeCompare([]byte(username), []byte(auth.Username)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(password), []byte(auth.Password)) == 1
	return userMatch && passMatch
}
