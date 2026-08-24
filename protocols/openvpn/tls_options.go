package openvpn

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
)

func parseTLSVersion(value string) (uint16, error) {
	switch strings.ToLower(value) {
	case "1.0", "1.0+", "1.1", "1.1+":
		return 0, fmt.Errorf("openvpn: TLS versions older than 1.2 are not supported")
	case "1.2", "1.2+":
		return tls.VersionTLS12, nil
	case "1.3", "1.3+":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("openvpn: invalid TLS version %q", value)
	}
}

func parseFingerprint(value string) ([]byte, error) {
	value = strings.ReplaceAll(strings.TrimSpace(value), ":", "")
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("openvpn: peer-fingerprint must be a SHA-256 fingerprint")
	}
	return decoded, nil
}
