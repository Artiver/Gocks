package http

import (
	"Gocks/global"
	"bytes"
	"encoding/base64"
	"log"
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

	if !strings.HasPrefix(authHeader, global.BasicAuthPrefix) {
		return false
	}

	encoded := strings.TrimPrefix(authHeader, global.BasicAuthPrefix)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Println("failed to decode ProxyConfig-Authorization header:", err)
		return false
	}

	authParts := strings.SplitN(string(decoded), ":", 2)
	if len(authParts) != 2 {
		return false
	}

	username, password := authParts[0], authParts[1]
	return username == global.ProxyConfig.Socks5Auth.Username && password == global.ProxyConfig.Socks5Auth.Password
}
