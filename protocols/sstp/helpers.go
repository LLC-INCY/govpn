package sstp

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"

	"github.com/bclswl0827/govpn"
)

func certificatePool(pem []byte) (*x509.CertPool, error) {
	if len(pem) == 0 {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("sstp: CA contains no certificates")
	}
	return pool, nil
}

func poolAddresses(value string) (network netip.Prefix, gateway, assigned netip.Addr, err error) {
	network, err = netip.ParsePrefix(value)
	if err != nil || !network.Addr().Is4() {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("sstp: invalid IPv4 pool %q", value)
	}
	network = network.Masked()
	if network.Bits() > 30 {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, errors.New("sstp: pool must contain a gateway and client address")
	}
	gateway = network.Addr().Next()
	assigned = gateway.Next()
	return network, gateway, assigned, nil
}

var _ govpn.Client = (*Client)(nil)
var _ govpn.Server = (*Server)(nil)
