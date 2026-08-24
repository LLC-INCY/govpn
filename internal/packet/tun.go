package packet

import (
	"io"
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

// Read implements tun.Device. With BatchSize 1, WireGuard supplies one buffer.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if d.closedFlag.Load() {
		return 0, ErrClosed
	}
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset > len(bufs[0]) {
		return 0, io.ErrShortBuffer
	}
	select {
	case packet := <-d.toProtocol:
		if len(packet) > len(bufs[0])-offset {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	case <-d.closed:
		return 0, ErrClosed
	}
}

// Write implements tun.Device. wireguard-go may pass a network-sized batch
// even when this device advertises BatchSize 1, because device.BatchSize uses
// the maximum of the bind and TUN batch sizes.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	if d.closedFlag.Load() {
		return 0, ErrClosed
	}
	if offset < 0 {
		return 0, io.ErrShortBuffer
	}
	for i, buffer := range bufs {
		if offset > len(buffer) {
			return i, io.ErrShortBuffer
		}
		packet := append([]byte(nil), buffer[offset:]...)
		select {
		case d.fromProtocol <- packet:
		case <-d.closed:
			return i, ErrClosed
		}
	}
	return len(bufs), nil
}

func (*Device) File() *os.File             { return nil }
func (d *Device) MTU() (int, error)        { return d.mtu, nil }
func (d *Device) Name() (string, error)    { return d.name, nil }
func (d *Device) Events() <-chan tun.Event { return d.events }
func (*Device) BatchSize() int             { return 1 }

var _ tun.Device = (*Device)(nil)
