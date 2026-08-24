package openvpn

import (
	"encoding/hex"
	"errors"
	"strings"
)

type StaticKey struct {
	Keys [2]KeyPair
}

func ParseStaticKey(value []byte) (StaticKey, error) {
	var encoded strings.Builder
	inKey := false
	for _, line := range strings.Split(strings.ReplaceAll(string(value), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		switch line {
		case "-----BEGIN OpenVPN Static key V1-----":
			inKey = true
		case "-----END OpenVPN Static key V1-----":
			inKey = false
		default:
			if inKey && line != "" && !strings.HasPrefix(line, "#") {
				encoded.WriteString(line)
			}
		}
	}
	decoded, err := hex.DecodeString(encoded.String())
	if err != nil {
		return StaticKey{}, errors.New("openvpn: invalid static key hex")
	}
	if len(decoded) != 256 {
		return StaticKey{}, errors.New("openvpn: static key must contain 2048 bits")
	}
	var key StaticKey
	copy(key.Keys[0].Cipher[:], decoded[:64])
	copy(key.Keys[0].HMAC[:], decoded[64:128])
	copy(key.Keys[1].Cipher[:], decoded[128:192])
	copy(key.Keys[1].HMAC[:], decoded[192:256])
	return key, nil
}

func (k StaticKey) directions(direction int, directionSet, server, crypt bool) (send, receive KeyPair, err error) {
	if crypt {
		if server {
			return k.Keys[0], k.Keys[1], nil
		}
		return k.Keys[1], k.Keys[0], nil
	}
	if !directionSet {
		return k.Keys[0], k.Keys[0], nil
	}
	switch direction {
	case 0:
		return k.Keys[0], k.Keys[1], nil
	case 1:
		return k.Keys[1], k.Keys[0], nil
	default:
		return KeyPair{}, KeyPair{}, errors.New("openvpn: key-direction must be 0 or 1")
	}
}
