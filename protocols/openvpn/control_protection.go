package openvpn

import (
	"errors"
	"net"

	protocol "github.com/bclswl0827/govpn/protocols/openvpn/internal"
)

func protectClientControl(conn net.Conn, config Config) (*protocol.ControlChannel, error) {
	mode, key, err := controlProtection(config.TLSAuth, config.TLSCrypt)
	if err != nil {
		return nil, err
	}
	return protocol.NewControlChannel(conn, mode, key, effectiveAuth(config), config.KeyDirection, config.KeyDirectionSet, false)
}

func protectServerControl(conn net.Conn, config ServerConfig) (*protocol.ControlChannel, error) {
	mode, key, err := controlProtection(config.TLSAuth, config.TLSCrypt)
	if err != nil {
		return nil, err
	}
	return protocol.NewControlChannel(conn, mode, key, effectiveServerAuth(config), config.KeyDirection, config.KeyDirectionSet, true)
}

func controlProtection(tlsAuth, tlsCrypt []byte) (protocol.ControlProtection, []byte, error) {
	if len(tlsAuth) != 0 && len(tlsCrypt) != 0 {
		return 0, nil, errors.New("openvpn: tls-auth and tls-crypt are mutually exclusive")
	}
	if len(tlsCrypt) != 0 {
		return protocol.ControlProtectionCrypt, tlsCrypt, nil
	}
	if len(tlsAuth) != 0 {
		return protocol.ControlProtectionAuth, tlsAuth, nil
	}
	return protocol.ControlProtectionNone, nil, nil
}
