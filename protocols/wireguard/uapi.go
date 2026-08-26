package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

func buildUAPI(privateKey string, listenPort int, peers []Peer) (string, error) {
	return buildUAPIWithMark(privateKey, listenPort, 0, peers)
}

func buildUAPIWithMark(privateKey string, listenPort int, firewallMark uint32, peers []Peer) (string, error) {
	privateHex, err := keyHex(privateKey, false)
	if err != nil {
		return "", fmt.Errorf("wireguard: private key: %w", err)
	}
	var config strings.Builder
	fmt.Fprintf(&config, "private_key=%s\n", privateHex)
	if listenPort != 0 {
		if listenPort < 0 || listenPort > 65535 {
			return "", fmt.Errorf("wireguard: listen port %d is out of range", listenPort)
		}
		fmt.Fprintf(&config, "listen_port=%d\n", listenPort)
	}
	if firewallMark != 0 {
		fmt.Fprintf(&config, "fwmark=%d\n", firewallMark)
	}
	config.WriteString("replace_peers=true\n")
	if err := appendPeerConfiguration(&config, peers); err != nil {
		return "", err
	}
	return config.String(), nil
}

func appendPeerConfiguration(config *strings.Builder, peers []Peer) error {
	for i, peer := range peers {
		publicHex, err := keyHex(peer.PublicKey, false)
		if err != nil {
			return fmt.Errorf("wireguard: peer %d public key: %w", i, err)
		}
		fmt.Fprintf(config, "public_key=%s\nprotocol_version=1\nreplace_allowed_ips=true\n", publicHex)
		if peer.PresharedKey != "" {
			pskHex, err := keyHex(peer.PresharedKey, true)
			if err != nil {
				return fmt.Errorf("wireguard: peer %d preshared key: %w", i, err)
			}
			fmt.Fprintf(config, "preshared_key=%s\n", pskHex)
		}
		if peer.Endpoint != "" {
			fmt.Fprintf(config, "endpoint=%s\n", peer.Endpoint)
		}
		if peer.Keepalive < 0 || peer.Keepalive > 65535 {
			return fmt.Errorf("wireguard: peer %d keepalive is out of range", i)
		}
		if peer.Keepalive != 0 {
			fmt.Fprintf(config, "persistent_keepalive_interval=%d\n", peer.Keepalive)
		}
		for _, allowed := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(allowed)
			if err != nil {
				return fmt.Errorf("wireguard: peer %d allowed IP %q: %w", i, allowed, err)
			}
			fmt.Fprintf(config, "allowed_ip=%s\n", prefix)
		}
	}
	return nil
}

func appendPeerUpdate(ctx context.Context, config *strings.Builder, update PeerUpdate) error {
	publicHex, err := keyHex(update.PublicKey, false)
	if err != nil {
		return fmt.Errorf("wireguard: peer public key: %w", err)
	}
	fmt.Fprintf(config, "public_key=%s\n", publicHex)
	if update.UpdateOnly {
		config.WriteString("update_only=true\n")
	}
	if update.Remove {
		if update.PresharedKey != nil || update.Endpoint != nil || update.Keepalive != nil ||
			update.ReplaceAllowedIPs || len(update.AllowedIPs) != 0 || len(update.RemoveAllowedIPs) != 0 {
			return errors.New("wireguard: remove peer update cannot contain configuration fields")
		}
		config.WriteString("remove=true\n")
		return nil
	}
	config.WriteString("protocol_version=1\n")
	if update.PresharedKey != nil {
		pskHex := strings.Repeat("0", 64)
		if *update.PresharedKey != "" {
			pskHex, err = keyHex(*update.PresharedKey, true)
			if err != nil {
				return fmt.Errorf("wireguard: peer preshared key: %w", err)
			}
		}
		fmt.Fprintf(config, "preshared_key=%s\n", pskHex)
	}
	if update.Endpoint != nil {
		if *update.Endpoint == "" {
			return errors.New("wireguard: endpoint cannot be cleared by the official UAPI")
		}
		endpoint, err := resolveEndpoint(ctx, *update.Endpoint)
		if err != nil {
			return fmt.Errorf("wireguard: peer endpoint: %w", err)
		}
		fmt.Fprintf(config, "endpoint=%s\n", endpoint)
	}
	if update.Keepalive != nil {
		if *update.Keepalive < 0 || *update.Keepalive > 65535 {
			return errors.New("wireguard: peer keepalive is out of range")
		}
		fmt.Fprintf(config, "persistent_keepalive_interval=%d\n", *update.Keepalive)
	}
	if update.ReplaceAllowedIPs {
		config.WriteString("replace_allowed_ips=true\n")
	}
	if err := appendAllowedIPs(config, update.AllowedIPs, false); err != nil {
		return err
	}
	return appendAllowedIPs(config, update.RemoveAllowedIPs, true)
}

func appendAllowedIPs(config *strings.Builder, allowedIPs []string, remove bool) error {
	prefix := ""
	if remove {
		prefix = "-"
	}
	for _, allowed := range allowedIPs {
		parsed, err := netip.ParsePrefix(allowed)
		if err != nil {
			return fmt.Errorf("wireguard: allowed IP %q: %w", allowed, err)
		}
		fmt.Fprintf(config, "allowed_ip=%s%s\n", prefix, parsed)
	}
	return nil
}

func keyHex(encoded string, allowZero bool) (string, error) {
	key, err := decodeKey(encoded)
	if err != nil {
		return "", err
	}
	if !allowZero {
		zero := true
		for _, b := range key {
			zero = zero && b == 0
		}
		if zero {
			return "", errors.New("key is all zero")
		}
	}
	return hex.EncodeToString(key), nil
}

func decodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("decoded length is %d, want 32", len(key))
	}
	return key, nil
}

func preparePeers(ctx context.Context, peers []Peer) ([]Peer, error) {
	prepared := make([]Peer, len(peers))
	copy(prepared, peers)
	for i := range prepared {
		prepared[i].AllowedIPs = append([]string(nil), peers[i].AllowedIPs...)
		if err := validateEndpointPreference(prepared[i].EndpointPreference); err != nil {
			return nil, fmt.Errorf("wireguard: peer %d: %w", i, err)
		}
		if prepared[i].Endpoint == "" {
			continue
		}
		candidates, err := resolveEndpointCandidates(ctx, prepared[i].Endpoint, prepared[i].EndpointPreference)
		if err != nil {
			return nil, fmt.Errorf("wireguard: peer %d endpoint: %w", i, err)
		}
		prepared[i].Endpoint = candidates[0]
		prepared[i].endpointCandidates = candidates
	}
	return prepared, nil
}

func resolveEndpoint(ctx context.Context, endpoint string) (string, error) {
	candidates, err := resolveEndpointCandidates(ctx, endpoint, EndpointPreferenceAuto)
	if err != nil {
		return "", err
	}
	return candidates[0], nil
}

func resolveEndpointCandidates(ctx context.Context, endpoint string, preference EndpointPreference) ([]string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return []string{net.JoinHostPort(addr.String(), port)}, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}
	ordered := orderedEndpointAddresses(addresses, preference)
	if len(ordered) == 0 {
		return nil, fmt.Errorf("resolve %q: no usable addresses", host)
	}
	candidates := make([]string, 0, len(ordered))
	for _, address := range ordered {
		candidates = append(candidates, net.JoinHostPort(address.String(), port))
	}
	return candidates, nil
}

func validateEndpointPreference(preference EndpointPreference) error {
	switch preference {
	case "", EndpointPreferenceAuto, EndpointPreferenceIPv4, EndpointPreferenceIPv6:
		return nil
	default:
		return fmt.Errorf("invalid endpoint preference %q", preference)
	}
}

func orderedEndpointAddresses(addresses []netip.Addr, preference EndpointPreference) []netip.Addr {
	unique := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() {
			continue
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		unique = append(unique, address)
	}
	if preference == "" || preference == EndpointPreferenceAuto {
		return unique
	}
	preferred := make([]netip.Addr, 0, len(unique))
	fallback := make([]netip.Addr, 0, len(unique))
	for _, address := range unique {
		matches := preference == EndpointPreferenceIPv4 && address.Is4() ||
			preference == EndpointPreferenceIPv6 && address.Is6()
		if matches {
			preferred = append(preferred, address)
		} else {
			fallback = append(fallback, address)
		}
	}
	return append(preferred, fallback...)
}
