package openvpn

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ParseConfig parses the client-side subset used by this implementation. It
// supports path-based and inline ca/cert/key directives. Relative paths are
// resolved from the current working directory. Unsupported directives are
// retained in Config.IgnoredDirectives instead of causing a parse failure.
func ParseConfig(value []byte) (*Config, error) {
	var err error
	config := &Config{}
	scanner := bufio.NewScanner(bytes.NewReader(value))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") {
			continue
		}
		if strings.HasPrefix(text, "<") && strings.HasSuffix(text, ">") && !strings.HasPrefix(text, "</") {
			name := strings.TrimSuffix(strings.TrimPrefix(text, "<"), ">")
			var content strings.Builder
			foundEnd := false
			for scanner.Scan() {
				line++
				if strings.TrimSpace(scanner.Text()) == "</"+name+">" {
					foundEnd = true
					break
				}
				content.WriteString(scanner.Text())
				content.WriteByte('\n')
			}
			if !foundEnd {
				return nil, fmt.Errorf("openvpn: line %d: unterminated <%s>", line, name)
			}
			if err := setInline(config, name, []byte(content.String())); err != nil {
				return nil, fmt.Errorf("openvpn: line %d: %w", line, err)
			}
			continue
		}
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		fields[0] = strings.TrimPrefix(strings.ToLower(fields[0]), "--")
		switch fields[0] {
		case "remote":
			if len(fields) < 2 || len(fields) > 4 {
				return nil, fmt.Errorf("openvpn: line %d: invalid remote", line)
			}
			remote := Remote{Host: fields[1]}
			if len(fields) >= 3 {
				remote.Port, err = strconv.Atoi(fields[2])
				if err != nil {
					return nil, fmt.Errorf("openvpn: line %d: invalid remote port", line)
				}
			}
			if len(fields) == 4 {
				remote.Protocol, err = parseClientProtocol(fields[3])
				if err != nil {
					return nil, fmt.Errorf("openvpn: line %d: %w", line, err)
				}
			}
			config.Remotes = append(config.Remotes, remote)
		case "port":
			if len(fields) != 2 {
				return nil, fmt.Errorf("openvpn: line %d: invalid port", line)
			}
			config.Port, err = strconv.Atoi(fields[1])
			if err != nil {
				return nil, fmt.Errorf("openvpn: line %d: invalid port", line)
			}
		case "ca", "cert", "key", "tls-auth", "tls-crypt":
			if len(fields) < 2 {
				return nil, fmt.Errorf("openvpn: line %d: missing %s path", line, fields[0])
			}
			if fields[0] != "tls-auth" && len(fields) != 2 {
				return nil, fmt.Errorf("openvpn: line %d: invalid %s", line, fields[0])
			}
			if fields[0] == "tls-auth" && len(fields) > 3 {
				return nil, fmt.Errorf("openvpn: line %d: invalid tls-auth", line)
			}
			value, readErr := os.ReadFile(resolvePath("", fields[1]))
			if readErr != nil {
				return nil, fmt.Errorf("openvpn: line %d: %w", line, readErr)
			}
			if err := setInline(config, fields[0], value); err != nil {
				return nil, err
			}
			if fields[0] == "tls-auth" && len(fields) == 3 {
				config.KeyDirection, err = strconv.Atoi(fields[2])
				if err != nil || (config.KeyDirection != 0 && config.KeyDirection != 1) {
					return nil, fmt.Errorf("openvpn: line %d: invalid tls-auth key direction", line)
				}
				config.KeyDirectionSet = true
			}
		case "cipher":
			if len(fields) != 2 {
				return nil, fmt.Errorf("openvpn: line %d: invalid cipher", line)
			}
			config.Cipher = normalizeCipherName(fields[1])
		case "data-ciphers", "ncp-ciphers":
			if len(fields) != 2 {
				return nil, fmt.Errorf("openvpn: line %d: invalid data-ciphers", line)
			}
			config.DataCiphers, err = parseDataCipherList(fields[1])
			if err != nil {
				return nil, fmt.Errorf("openvpn: line %d: %w", line, err)
			}
		case "data-ciphers-fallback":
			if len(fields) != 2 || !supportedDataCipher(fields[1]) {
				return nil, fmt.Errorf("openvpn: line %d: unsupported data-ciphers-fallback", line)
			}
			config.DataCipherFallback = normalizeCipherName(fields[1])
		case "auth":
			if len(fields) != 2 {
				return nil, fmt.Errorf("openvpn: line %d: invalid auth", line)
			}
			config.Auth = fields[1]
		case "peer-fingerprint":
			if len(fields) < 2 {
				return nil, fmt.Errorf("openvpn: line %d: peer-fingerprint requires at least one fingerprint", line)
			}
			for _, value := range fields[1:] {
				fingerprint, parseErr := parseFingerprint(value)
				if parseErr != nil {
					return nil, fmt.Errorf("openvpn: line %d: %w", line, parseErr)
				}
				config.PeerFingerprints = append(config.PeerFingerprints, fingerprint)
			}
		case "verify-x509-name":
			if len(fields) < 2 || len(fields) > 3 {
				return nil, fmt.Errorf("openvpn: line %d: invalid verify-x509-name", line)
			}
			config.VerifyX509Name = fields[1]
			config.VerifyX509Type = "name"
			if len(fields) == 3 {
				config.VerifyX509Type = fields[2]
			}
		case "remote-cert-tls":
			if len(fields) != 2 || (fields[1] != "server" && fields[1] != "client") {
				return nil, fmt.Errorf("openvpn: line %d: invalid remote-cert-tls", line)
			}
			config.RemoteCertTLS = fields[1]
		case "tls-version-min", "tls-version-max":
			if len(fields) < 2 || len(fields) > 3 {
				return nil, fmt.Errorf("openvpn: line %d: invalid %s", line, fields[0])
			}
			version, parseErr := parseTLSVersion(fields[1])
			if parseErr != nil {
				return nil, fmt.Errorf("openvpn: line %d: %w", line, parseErr)
			}
			if fields[0] == "tls-version-min" {
				config.TLSVersionMin = version
			} else {
				config.TLSVersionMax = version
			}
		case "auth-user-pass":
			// Credentials are supplied by the caller through Config. Ignore this
			// directive so parsing never reads credentials from the filesystem.
			addIgnoredDirective(config, fields[0])
		case "comp-lzo":
			if len(fields) > 2 {
				return nil, fmt.Errorf("openvpn: line %d: invalid comp-lzo", line)
			}
			mode := "adaptive"
			if len(fields) == 2 {
				mode = strings.ToLower(fields[1])
			}
			switch mode {
			case "adaptive", "yes":
				config.Compression = "lzo"
			case "no":
				config.Compression = ""
			default:
				return nil, fmt.Errorf("openvpn: line %d: unsupported comp-lzo mode %q", line, mode)
			}
		case "tun-mtu":
			if len(fields) != 2 {
				return nil, fmt.Errorf("openvpn: line %d: invalid tun-mtu", line)
			}
			config.MTU, err = strconv.Atoi(fields[1])
			if err != nil {
				return nil, fmt.Errorf("openvpn: line %d: invalid tun-mtu", line)
			}
		case "proto":
			if len(fields) != 2 {
				return nil, fmt.Errorf("openvpn: line %d: invalid proto", line)
			}
			config.Protocol, err = parseClientProtocol(fields[1])
			if err != nil {
				return nil, fmt.Errorf("openvpn: line %d: %w", line, err)
			}
		case "key-direction":
			if len(fields) != 2 {
				return nil, fmt.Errorf("openvpn: line %d: invalid key-direction", line)
			}
			config.KeyDirection, err = strconv.Atoi(fields[1])
			if err != nil {
				return nil, fmt.Errorf("openvpn: line %d: invalid key-direction", line)
			}
			config.KeyDirectionSet = true
		case "client", "dev", "dev-type", "nobind", "persist-key", "persist-tun", "verb", "mute-replay-warnings", "auth-nocache", "pull", "resolv-retry", "script-security", "dhcp-option":
			// These directives affect host integration, logging, or retry policy;
			// they do not change this library's in-memory protocol engine.
			addIgnoredDirective(config, fields[0])
		default:
			addIgnoredDirective(config, fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if config.Port == 0 {
		config.Port = 1194
	}
	for index := range config.Remotes {
		if config.Remotes[index].Port == 0 {
			config.Remotes[index].Port = config.Port
		}
		if config.Remotes[index].Protocol == "" {
			config.Remotes[index].Protocol = config.Protocol
		}
	}
	if len(config.Remotes) != 0 {
		config.Remote = config.Remotes[0].Host
		config.Port = config.Remotes[0].Port
		if config.Remotes[0].Protocol != "" {
			config.Protocol = config.Remotes[0].Protocol
		}
	}
	return config, nil
}

func parseClientProtocol(value string) (string, error) {
	switch strings.ToLower(value) {
	case "udp", "udp4", "udp6":
		return strings.ToLower(value), nil
	case "tcp", "tcp-client":
		return "tcp", nil
	case "tcp4", "tcp4-client":
		return "tcp4", nil
	case "tcp6", "tcp6-client":
		return "tcp6", nil
	default:
		return "", fmt.Errorf("unsupported proto %q", value)
	}
}
