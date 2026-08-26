package wireguard

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/bclswl0827/govpn"
)

// ParseConfig reads official wg and wg-quick configuration fields. Host route,
// DNS and lifecycle values are preserved in Config but are not executed.
func ParseConfig(r io.Reader) (*Config, error) {
	config := &Config{}
	section := ""
	scanner := bufio.NewScanner(r)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
			section = strings.ToLower(strings.TrimSpace(text[1 : len(text)-1]))
			if section == "peer" {
				config.Peers = append(config.Peers, Peer{})
			}
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return nil, fmt.Errorf("wireguard: line %d: expected key=value", line)
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				config.PrivateKey = value
			case "address":
				config.Address = append(config.Address, splitList(value)...)
			case "dns":
				config.DNS = append(config.DNS, splitList(value)...)
			case "mtu":
				parsed, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("wireguard: line %d: invalid MTU %q", line, value)
				}
				config.MTU = parsed
			case "listenport":
				parsed, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("wireguard: line %d: invalid listen port %q", line, value)
				}
				config.ListenPort = parsed
			case "fwmark":
				parsed, err := parseOptionalUint32(value)
				if err != nil {
					return nil, fmt.Errorf("wireguard: line %d: invalid firewall mark %q", line, value)
				}
				config.FirewallMark = parsed
			case "table":
				config.Table = value
			case "preup":
				config.PreUp = append(config.PreUp, value)
			case "postup":
				config.PostUp = append(config.PostUp, value)
			case "predown":
				config.PreDown = append(config.PreDown, value)
			case "postdown":
				config.PostDown = append(config.PostDown, value)
			case "saveconfig":
				parsed, err := strconv.ParseBool(value)
				if err != nil {
					return nil, fmt.Errorf("wireguard: line %d: invalid SaveConfig %q", line, value)
				}
				config.SaveConfig = parsed
			default:
				return nil, fmt.Errorf("wireguard: line %d: unsupported interface key %q", line, key)
			}
		case "peer":
			if len(config.Peers) == 0 {
				return nil, fmt.Errorf("wireguard: line %d: peer value before section", line)
			}
			peer := &config.Peers[len(config.Peers)-1]
			switch key {
			case "publickey":
				peer.PublicKey = value
			case "presharedkey":
				peer.PresharedKey = value
			case "endpoint":
				peer.Endpoint = value
			case "endpointpreference":
				preference := EndpointPreference(strings.ToLower(value))
				if err := validateEndpointPreference(preference); err != nil {
					return nil, fmt.Errorf("wireguard: line %d: %w", line, err)
				}
				peer.EndpointPreference = preference
			case "allowedips":
				peer.AllowedIPs = append(peer.AllowedIPs, splitList(value)...)
			case "persistentkeepalive":
				parsed, err := parseOptionalInt(value)
				if err != nil {
					return nil, fmt.Errorf("wireguard: line %d: invalid persistent keepalive %q", line, value)
				}
				peer.Keepalive = parsed
			default:
				return nil, fmt.Errorf("wireguard: line %d: unsupported peer key %q", line, key)
			}
		default:
			return nil, fmt.Errorf("wireguard: line %d: value outside a section", line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return config, nil
}

func parseOptionalUint32(value string) (uint32, error) {
	if strings.EqualFold(strings.TrimSpace(value), "off") {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 0, 32)
	return uint32(parsed), err
}

func parseOptionalInt(value string) (int, error) {
	if strings.EqualFold(strings.TrimSpace(value), "off") {
		return 0, nil
	}
	return strconv.Atoi(value)
}

func ParseConfigFile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ParseConfig(file)
}

func splitList(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}

var _ govpn.Client = (*Client)(nil)
var _ govpn.Server = (*Server)(nil)
