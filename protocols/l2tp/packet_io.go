package l2tp

import (
	"context"
	"io"

	"github.com/bclswl0827/govpn/internal/packet"
)

type packetIO struct {
	ctx    context.Context
	device *packet.Device
}

func (p packetIO) Read(destination []byte) (int, error) {
	value, err := p.device.ReadPacket(p.ctx)
	if err != nil {
		return 0, err
	}
	if len(value) > len(destination) {
		return 0, io.ErrShortBuffer
	}
	return copy(destination, value), nil
}

func (p packetIO) Write(value []byte) (int, error) {
	if err := p.device.WritePacket(p.ctx, value); err != nil {
		return 0, err
	}
	return len(value), nil
}
