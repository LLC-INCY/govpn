package openvpn

import (
	"errors"
	"strings"
)

func validateClient(config Config) error {
	if config.Remote == "" || config.Port <= 0 || config.Port > 65535 {
		return errors.New("openvpn: valid remote and port are required")
	}
	switch transportNetwork(config) {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
	default:
		return errors.New("openvpn: unsupported transport protocol")
	}
	if len(config.CA) == 0 && len(config.PeerFingerprints) == 0 {
		return errors.New("openvpn: CA or peer-fingerprint is required")
	}
	if (len(config.Cert) == 0) != (len(config.Key) == 0) {
		return errors.New("openvpn: certificate and key must be provided together")
	}
	if config.Cipher != "" && !supportedDataCipher(config.Cipher) {
		return errors.New("openvpn: unsupported cipher")
	}
	for _, name := range config.DataCiphers {
		if !supportedDataCipher(name) {
			return errors.New("openvpn: unsupported data cipher")
		}
	}
	if config.DataCipherFallback != "" && !supportedDataCipher(config.DataCipherFallback) {
		return errors.New("openvpn: unsupported data cipher fallback")
	}
	if !supportedAuthDigest(config.Auth) {
		return errors.New("openvpn: unsupported authentication digest")
	}
	if config.Compression != "" && !strings.EqualFold(config.Compression, "lzo") {
		return errors.New("openvpn: unsupported compression")
	}
	if config.MTU < 0 || config.MTU > 65535 || (config.MTU != 0 && config.MTU < 576) {
		return errors.New("openvpn: MTU is out of range")
	}
	if len(config.TLSAuth) != 0 && len(config.TLSCrypt) != 0 {
		return errors.New("openvpn: tls-auth and tls-crypt are mutually exclusive")
	}
	if config.KeyDirectionSet && config.KeyDirection != 0 && config.KeyDirection != 1 {
		return errors.New("openvpn: key-direction must be 0 or 1")
	}
	if config.TLSVersionMin != 0 && config.TLSVersionMax != 0 && config.TLSVersionMin > config.TLSVersionMax {
		return errors.New("openvpn: tls-version-min exceeds tls-version-max")
	}
	if config.Shape != 0 {
		return errors.New("openvpn: Shape is unsupported")
	}
	return nil
}

func validateServer(config ServerConfig) error {
	if config.ListenPort <= 0 || config.ListenPort > 65535 {
		return errors.New("openvpn: valid listen port is required")
	}
	switch serverTransportNetwork(config) {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
	default:
		return errors.New("openvpn: unsupported server transport protocol")
	}
	if len(config.Cert) == 0 || len(config.Key) == 0 || len(config.CA) == 0 {
		return errors.New("openvpn: CA, certificate, and key are required")
	}
	for _, name := range effectiveServerDataCiphers(config) {
		if !supportedDataCipher(name) {
			return errors.New("openvpn: unsupported server data cipher")
		}
	}
	if config.DataCipherFallback != "" && !supportedDataCipher(config.DataCipherFallback) {
		return errors.New("openvpn: unsupported server data cipher fallback")
	}
	if !supportedAuthDigest(config.Auth) {
		return errors.New("openvpn: unsupported server authentication digest")
	}
	if len(config.TLSAuth) != 0 && len(config.TLSCrypt) != 0 {
		return errors.New("openvpn: tls-auth and tls-crypt are mutually exclusive")
	}
	if config.KeyDirectionSet && config.KeyDirection != 0 && config.KeyDirection != 1 {
		return errors.New("openvpn: key-direction must be 0 or 1")
	}
	if config.TLSVersionMin != 0 && config.TLSVersionMax != 0 && config.TLSVersionMin > config.TLSVersionMax {
		return errors.New("openvpn: server tls-version-min exceeds tls-version-max")
	}
	if config.VerifyClientCert != "" && config.VerifyClientCert != "require" && config.VerifyClientCert != "optional" && config.VerifyClientCert != "none" {
		return errors.New("openvpn: verify-client-cert must be require, optional, or none")
	}
	if config.Pool == "" && config.Pool6 == "" {
		return errors.New("openvpn: IPv4 or IPv6 address pool is required")
	}
	if config.MTU < 0 || config.MTU > 65535 || (config.MTU != 0 && config.MTU < 576) {
		return errors.New("openvpn: MTU is out of range")
	}
	if config.Shape != 0 {
		return errors.New("openvpn: Shape is unsupported")
	}
	return nil
}
