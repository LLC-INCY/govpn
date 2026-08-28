// Package transport contains lifecycle helpers shared by VPN transports.
package transport

import (
	"errors"
	"io"
	"net"

	"github.com/bclswl0827/govpn/internal/packet"
)

// NormalizeError converts expected stream, socket, and packet-device shutdown
// errors to nil while preserving operational failures.
func NormalizeError(err error) error {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, packet.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
