package wireguard

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

var ErrNotStarted = errors.New("wireguard: device has not been started")

func parseStatus(configuration string) (Status, error) {
	var status Status
	var current *PeerStatus
	var privateKey []byte
	var handshakeSeconds, handshakeNanoseconds int64
	finishPeer := func() {
		if current != nil && (handshakeSeconds != 0 || handshakeNanoseconds != 0) {
			current.LastHandshake = time.Unix(handshakeSeconds, handshakeNanoseconds)
		}
		handshakeSeconds, handshakeNanoseconds = 0, 0
	}

	scanner := bufio.NewScanner(strings.NewReader(configuration))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Status{}, fmt.Errorf("wireguard: malformed UAPI status line %q", line)
		}
		if key == "public_key" {
			finishPeer()
			encoded, err := hexToBase64Key(value)
			if err != nil {
				return Status{}, fmt.Errorf("wireguard: peer public key: %w", err)
			}
			status.Peers = append(status.Peers, PeerStatus{PublicKey: encoded})
			current = &status.Peers[len(status.Peers)-1]
			continue
		}
		if current == nil {
			switch key {
			case "private_key":
				decoded, err := hex.DecodeString(value)
				if err != nil || len(decoded) != curve25519.ScalarSize {
					return Status{}, errors.New("wireguard: invalid private key in UAPI status")
				}
				privateKey = decoded
			case "listen_port":
				parsed, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					return Status{}, fmt.Errorf("wireguard: invalid UAPI listen port: %w", err)
				}
				status.ListenPort = int(parsed)
			case "fwmark":
				parsed, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return Status{}, fmt.Errorf("wireguard: invalid UAPI firewall mark: %w", err)
				}
				status.FirewallMark = uint32(parsed)
			}
			continue
		}
		var err error
		switch key {
		case "endpoint":
			current.Endpoint = value
		case "allowed_ip":
			current.AllowedIPs = append(current.AllowedIPs, value)
		case "persistent_keepalive_interval":
			var parsed uint64
			parsed, err = strconv.ParseUint(value, 10, 16)
			current.Keepalive = int(parsed)
		case "last_handshake_time_sec":
			handshakeSeconds, err = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			handshakeNanoseconds, err = strconv.ParseInt(value, 10, 64)
		case "tx_bytes":
			current.TransmitBytes, err = strconv.ParseUint(value, 10, 64)
		case "rx_bytes":
			current.ReceiveBytes, err = strconv.ParseUint(value, 10, 64)
		}
		if err != nil {
			return Status{}, fmt.Errorf("wireguard: invalid UAPI %s: %w", key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return Status{}, err
	}
	finishPeer()
	if len(privateKey) != 0 {
		privateKey[0] &= 248
		privateKey[31] = privateKey[31]&127 | 64
		public, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return Status{}, fmt.Errorf("wireguard: derive status public key: %w", err)
		}
		status.PublicKey = base64.StdEncoding.EncodeToString(public)
	}
	return status, nil
}

func hexToBase64Key(value string) (string, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("decoded length is %d, want 32", len(decoded))
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}
