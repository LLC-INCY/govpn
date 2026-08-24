package openvpn

import (
	"errors"
	"net"
	"sync"
	"time"
)

// PeerConn turns one remote address on a PacketConn into a net.Conn. The first
// datagram is read by the caller and passed to ServerEndpoint before PeerConn
// starts reading subsequent datagrams.
type PeerConn struct {
	PacketConn net.PacketConn
	Peer       net.Addr
	writeMu    sync.Mutex
}

func (c *PeerConn) Read(buffer []byte) (int, error) {
	for {
		n, peer, err := c.PacketConn.ReadFrom(buffer)
		if err != nil {
			return 0, err
		}
		if peer.String() == c.Peer.String() {
			return n, nil
		}
	}
}

func (c *PeerConn) Write(buffer []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.PacketConn.WriteTo(buffer, c.Peer)
}

func (c *PeerConn) Close() error         { return c.PacketConn.Close() }
func (c *PeerConn) LocalAddr() net.Addr  { return c.PacketConn.LocalAddr() }
func (c *PeerConn) RemoteAddr() net.Addr { return c.Peer }
func (c *PeerConn) SetDeadline(t time.Time) error {
	return errors.Join(c.PacketConn.SetReadDeadline(t), c.PacketConn.SetWriteDeadline(t))
}
func (c *PeerConn) SetReadDeadline(t time.Time) error  { return c.PacketConn.SetReadDeadline(t) }
func (c *PeerConn) SetWriteDeadline(t time.Time) error { return c.PacketConn.SetWriteDeadline(t) }

var _ net.Conn = (*PeerConn)(nil)
