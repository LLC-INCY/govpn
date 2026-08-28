package sstp

import (
	"crypto/x509"
	"errors"

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

var _ govpn.Client = (*Client)(nil)
var _ govpn.Server = (*Server)(nil)
