package openvpn

import (
	"fmt"
	"strings"
)

var defaultDataCiphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}

func normalizeCipherName(name string) string {
	return strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(name, "?")))
}

func supportedDataCipher(name string) bool {
	switch normalizeCipherName(name) {
	case "AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305",
		"AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "BF-CBC":
		return true
	default:
		return false
	}
}

func supportedAuthDigest(name string) bool {
	switch strings.ToUpper(name) {
	case "", "MD5", "SHA1", "SHA-1", "SHA224", "SHA-224", "SHA256", "SHA-256", "SHA384", "SHA-384", "SHA512", "SHA-512":
		return true
	default:
		return false
	}
}

func parseDataCipherList(value string) ([]string, error) {
	if len(value) > 127 {
		return nil, fmt.Errorf("openvpn: data-ciphers exceeds 127 bytes")
	}
	var result []string
	seen := make(map[string]struct{})
	for _, item := range strings.Split(value, ":") {
		optional := strings.HasPrefix(item, "?")
		name := normalizeCipherName(item)
		if name == "DEFAULT" {
			for _, defaultCipher := range defaultDataCiphers {
				if _, ok := seen[defaultCipher]; !ok {
					seen[defaultCipher] = struct{}{}
					result = append(result, defaultCipher)
				}
			}
			continue
		}
		if name == "" || !supportedDataCipher(name) {
			if optional {
				continue
			}
			return nil, fmt.Errorf("openvpn: unsupported data cipher %q", strings.TrimPrefix(item, "?"))
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			result = append(result, name)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("openvpn: data-ciphers contains no supported cipher")
	}
	return result, nil
}

func effectiveClientDataCiphers(config Config) []string {
	if len(config.DataCiphers) != 0 {
		return append([]string(nil), config.DataCiphers...)
	}
	result := append([]string(nil), defaultDataCiphers...)
	legacyCipher := normalizeCipherName(config.Cipher)
	if legacyCipher == "" {
		return result
	}
	for _, name := range result {
		if name == legacyCipher {
			return result
		}
	}
	return append(result, legacyCipher)
}

func effectiveServerDataCiphers(config ServerConfig) []string {
	if len(config.DataCiphers) != 0 {
		return append([]string(nil), config.DataCiphers...)
	}
	if config.Cipher != "" {
		return []string{normalizeCipherName(config.Cipher)}
	}
	return append([]string(nil), defaultDataCiphers...)
}

func selectDataCipher(server, client []string, fallback string) (string, error) {
	clientSet := make(map[string]struct{}, len(client))
	for _, name := range client {
		clientSet[normalizeCipherName(name)] = struct{}{}
	}
	for _, name := range server {
		name = normalizeCipherName(name)
		if _, ok := clientSet[name]; ok {
			return name, nil
		}
	}
	if fallback = normalizeCipherName(fallback); fallback != "" && supportedDataCipher(fallback) {
		return fallback, nil
	}
	return "", fmt.Errorf("openvpn: client and server have no common data cipher")
}

func parsePeerDataCiphers(peerInfo string) []string {
	for _, line := range strings.Split(peerInfo, "\n") {
		if strings.HasPrefix(line, "IV_CIPHERS=") {
			value := strings.TrimPrefix(line, "IV_CIPHERS=")
			result, err := parseDataCipherList(value)
			if err == nil {
				return result
			}
		}
	}
	return nil
}
