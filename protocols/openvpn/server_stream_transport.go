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

type serverStreamTransport struct {
	listener net.Listener
	device   *packet.Device
	config   ServerConfig
	mu       sync.Mutex
	child    *transport
	once     sync.Once
}

func newServerStreamTransport(listener net.Listener, device *packet.Device, config ServerConfig) *serverStreamTransport {
	return &serverStreamTransport{listener: listener, device: device, config: config}
}

func (s *serverStreamTransport) Close() error {
	var err error
	s.once.Do(func() {
		s.mu.Lock()
		child := s.child
		s.mu.Unlock()
		if child != nil {
			err = child.Close()
		}
		err = errors.Join(err, s.listener.Close(), s.device.Close())
	})
	return err
}

func (s *serverStreamTransport) accept(tlsConfig *tls.Config, network netip.Prefix, gateway, assigned netip.Addr, network6 netip.Prefix, gateway6, assigned6 netip.Addr, done chan<- error) {
	rawConn, err := s.listener.Accept()
	if err != nil {
		done <- normalizeError(err)
		return
	}
	stream := protocol.NewStreamConn(rawConn)
	protectedConn, err := protectServerControl(stream, s.config)
	if err != nil {
		_ = s.Close()
		done <- err
		return
	}
	first := make([]byte, 65535)
	n, err := protectedConn.Read(first)
	if err != nil {
		_ = s.Close()
		done <- err
		return
	}
	child, err := establishServerSession(protectedConn, first[:n], s.device, s.config, tlsConfig, network, gateway, assigned, network6, gateway6, assigned6)
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
