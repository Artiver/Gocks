package http

import (
	"Gocks/utils"
	"bytes"
	"encoding/base64"
	"log"
	"strings"
)

const basicAuthHeader = "proxy-authorization"

func parseHeaders(data []byte) map[string]string {
	headers := make(map[string]string)
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		parts := strings.SplitN(string(line), ": ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == basicAuthHeader {
			headers[basicAuthHeader] = parts[1]
			break
		}
	}
	return headers
}

func checkProxyAuthorization(headers map[string]string) bool {
	authHeader, exists := headers[basicAuthHeader]
	if !exists {
		return false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}

	encoded := strings.TrimPrefix(authHeader, prefix)
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
	return username == utils.Config.Username && password == utils.Config.Password
}
