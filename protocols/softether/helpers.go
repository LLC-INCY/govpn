package softether

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"

	"github.com/bclswl0827/govpn"
)

func clientTLSConfig(config Config) (*tls.Config, error) {
	roots := (*x509.CertPool)(nil)
	if len(config.CA) != 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(config.CA) {
			return nil, errors.New("softether: CA contains no certificates")
		}
	}
	serverName := config.ServerName
	if serverName == "" {
		serverName = config.Server
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName, InsecureSkipVerify: config.SkipVerify}, nil
}

func parseDNS(values []string) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			return nil, fmt.Errorf("softether: invalid IPv4 DNS address %q", value)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

var _ govpn.Client = (*Client)(nil)
var _ govpn.Server = (*Server)(nil)
