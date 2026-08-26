package openvpn

import (
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/bclswl0827/govpn/internal/packet"
	protocol "github.com/bclswl0827/govpn/protocols/openvpn/internal"
)

type serverTransport struct {
	packetConn net.PacketConn
	device     *packet.Device
	config     ServerConfig
	mu         sync.Mutex
	child      *transport
	once       sync.Once
}

func newServerTransport(conn net.PacketConn, device *packet.Device, config ServerConfig) *serverTransport {
	return &serverTransport{packetConn: conn, device: device, config: config}
}

func (s *serverTransport) Close() error {
	var err error
	s.once.Do(func() {
		s.mu.Lock()
		child := s.child
		s.mu.Unlock()
		if child != nil {
			err = child.Close()
		}
		err = errors.Join(err, s.packetConn.Close(), s.device.Close())
	})
	return err
}

func (s *serverTransport) accept(tlsConfig *tls.Config, network netip.Prefix, gateway, assigned netip.Addr, network6 netip.Prefix, gateway6, assigned6 netip.Addr, done chan<- error) {
	buffer := make([]byte, 65535)
	n, peer, err := s.packetConn.ReadFrom(buffer)
	if err != nil {
		done <- normalizeError(err)
		return
	}
	peerConn := &protocol.PeerConn{PacketConn: s.packetConn, Peer: peer}
	protectedConn, err := protectServerControl(peerConn, s.config)
	if err != nil {
		_ = s.Close()
		done <- err
		return
	}
	firstDatagram, err := protectedConn.Unwrap(buffer[:n])
	if err != nil {
		_ = s.Close()
		done <- err
		return
	}
	child, err := establishServerSession(protectedConn, firstDatagram, s.device, s.config, tlsConfig, network, gateway, assigned, network6, gateway6, assigned6)
	if err != nil {
		_ = s.Close()
		done <- err
		return
	}
	s.mu.Lock()
	s.child = child
	s.mu.Unlock()
	child.run(done)
}
