package openvpn

import (
	"context"
	"net"
	"time"

	"github.com/bclswl0827/govpn"
)

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

var _ govpn.Client = (*Client)(nil)
var _ govpn.Server = (*Server)(nil)
