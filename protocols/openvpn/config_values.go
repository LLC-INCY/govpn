package openvpn

import (
	"path/filepath"
	"strings"
)

func setInline(config *Config, name string, value []byte) error {
	switch name {
	case "ca":
		config.CA = append([]byte(nil), value...)
	case "cert":
		config.Cert = append([]byte(nil), value...)
	case "key":
		config.Key = append([]byte(nil), value...)
	case "tls-auth":
		config.TLSAuth = append([]byte(nil), value...)
	case "tls-crypt":
		config.TLSCrypt = append([]byte(nil), value...)
	case "auth-user-pass":
		// Credentials are supplied by the caller through Config.
		addIgnoredDirective(config, name)
	default:
		addIgnoredDirective(config, name)
	}
	return nil
}

func addIgnoredDirective(config *Config, name string) {
	name = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "--")
	for _, existing := range config.IgnoredDirectives {
		if existing == name {
			return
		}
	}
	config.IgnoredDirectives = append(config.IgnoredDirectives, name)
}

func resolvePath(directory, value string) string {
	value = strings.Trim(value, "\"")
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(directory, value)
}
