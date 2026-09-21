package http

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"gocks/internal/config"
	"gocks/internal/constant"
	"log"
	"net/http"
	"strings"
)

func parseHeaders(data []byte) map[string]string {
	headers := make(map[string]string)
	lines := bytes.Split(data, config.CRLF)
	for _, line := range lines {
		parts := strings.SplitN(string(line), ": ", 2)
		if len(parts) == 2 && parts[0] == constant.BasicAuthHeader {
			headers[constant.BasicAuthHeader] = parts[1]
			break
		}
	}
	return headers
}

func checkProxyAuthorization(headers map[string]string) bool {
	authHeader, exists := headers[constant.BasicAuthHeader]
	if !exists {
		return false
	}
	return checkAuthHeader(authHeader)
}

func checkProxyAuthorizationFromHeader(header http.Header) bool {
	return checkAuthHeader(header.Get(constant.BasicAuthHeader))
}

func checkAuthHeader(authHeader string) bool {
	if !strings.HasPrefix(authHeader, constant.BasicAuthPrefix) {
		return false
	}

	encoded := strings.TrimPrefix(authHeader, constant.BasicAuthPrefix)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Println("failed to decode Proxy-Authorization header:", err)
		return false
	}

	authParts := strings.SplitN(string(decoded), ":", 2)
	if len(authParts) != 2 {
		return false
	}

	username, password := authParts[0], authParts[1]
	expectedUser := config.ProxyConfig.Username
	expectedPass := config.ProxyConfig.Password

	userMatch := subtle.ConstantTimeCompare([]byte(username), []byte(expectedUser)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(password), []byte(expectedPass)) == 1
	return userMatch && passMatch
}
