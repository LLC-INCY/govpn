package openvpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
)

func poolAddresses(value string) (netip.Prefix, netip.Addr, netip.Addr, error) {
	network, err := netip.ParsePrefix(value)
	if err != nil || !network.Addr().Is4() {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("openvpn: invalid IPv4 pool %q", value)
	}
	network = network.Masked()
	if network.Bits() > 30 {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, errors.New("openvpn: pool has fewer than two usable addresses")
	}
	gateway := network.Addr().Next()
	return network, gateway, gateway.Next(), nil
}

func prefixNetmask(bits int) string {
	mask := net.CIDRMask(bits, 32)
	return net.IP(mask).String()
}

func setHandshakeDeadline(ctx context.Context, conn net.Conn) {
	deadline := time.Now().Add(15 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
}

func normalizeError(err error) error {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, packet.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

var _ govpn.Client = (*Client)(nil)
var _ govpn.Server = (*Server)(nil)
