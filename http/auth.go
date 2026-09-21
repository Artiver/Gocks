package http

import (
	"Gocks/global"
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"log"
	"net/http"
	"strings"
)

func parseHeaders(data []byte) map[string]string {
	headers := make(map[string]string)
	lines := bytes.Split(data, global.CRLF)
	for _, line := range lines {
		parts := strings.SplitN(string(line), ": ", 2)
		if len(parts) == 2 && parts[0] == global.BasicAuthHeader {
			headers[global.BasicAuthHeader] = parts[1]
			break
		}
	}
	return headers
}

func checkProxyAuthorization(headers map[string]string) bool {
	authHeader, exists := headers[global.BasicAuthHeader]
	if !exists {
		return false
	}
	return checkAuthHeader(authHeader)
}

// checkProxyAuthorizationFromHeader 从 http.Header 检查认证
func checkProxyAuthorizationFromHeader(header http.Header) bool {
	return checkAuthHeader(header.Get(global.BasicAuthHeader))
}

// checkAuthHeader 校验单个 Proxy-Authorization 头值
func checkAuthHeader(authHeader string) bool {
	if !strings.HasPrefix(authHeader, global.BasicAuthPrefix) {
		return false
	}

	encoded := strings.TrimPrefix(authHeader, global.BasicAuthPrefix)
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
	expectedUser := global.ProxyConfig.Username
	expectedPass := global.ProxyConfig.Password

	userMatch := subtle.ConstantTimeCompare([]byte(username), []byte(expectedUser)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(password), []byte(expectedPass)) == 1
	return userMatch && passMatch
}
