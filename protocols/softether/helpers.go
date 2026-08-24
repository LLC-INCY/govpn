package softether

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
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

func poolAddresses(value string) (netip.Prefix, netip.Addr, netip.Addr, error) {
	network, err := netip.ParsePrefix(value)
	if err != nil || !network.Addr().Is4() {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("softether: invalid IPv4 pool %q", value)
	}
	network = network.Masked()
	if network.Bits() > 30 {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, errors.New("softether: pool has fewer than two usable addresses")
	}
	gateway := network.Addr().Next()
	return network, gateway, gateway.Next(), nil
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

func normalizeError(err error) error {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, packet.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

var _ govpn.Client = (*Client)(nil)
var _ govpn.Server = (*Server)(nil)
