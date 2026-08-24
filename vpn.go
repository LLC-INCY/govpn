package govpn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	userspacestack "github.com/bclswl0827/govpn/internal/netstack"
)

// Protocol identifies a supported VPN wire protocol.
type Protocol string

const (
	ProtocolWireGuard Protocol = "wireguard"
	ProtocolSSTP      Protocol = "sstp"
	ProtocolOpenVPN   Protocol = "openvpn"
	ProtocolSoftEther Protocol = "softether"
)

// Starter is the common lifecycle implemented by every protocol client and
// server. Start completes protocol setup and returns the same socket surface
// for both roles.
type Starter interface {
	Start(context.Context) (*Session, error)
}

// Client and Server deliberately have the same method set. The distinction is
// semantic: a client initiates a VPN transport and a server accepts one.
type Client interface{ Starter }
type Server interface{ Starter }

// PacketDevice is the raw-IP boundary between a VPN protocol and gVisor.
// Protocol packages normally supply this internally; it is exported to allow
// additional protocols to integrate without depending on implementation
// details of the gVisor adapter.
type PacketDevice interface {
	Inject(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}

// Session exposes network operations backed by the in-process gVisor stack.
type Session struct {
	stack *userspacestack.Stack

	closeTransport func() error
	terminalDone   chan struct{}
	terminalMu     sync.RWMutex
	terminalErr    error
	closeOnce      sync.Once
	closeErr       error
}

// NewSession connects a running protocol packet device to a new gVisor stack.
// closeTransport tears down the protocol, while done reports its terminal
// error. Protocol implementations use this constructor after authentication.
func NewSession(addresses []netip.Prefix, mtu uint32, device PacketDevice, closeTransport func() error, done <-chan error) (*Session, error) {
	if closeTransport == nil {
		closeTransport = func() error { return nil }
	}
	s, err := userspacestack.New(addresses, mtu, device)
	if err != nil {
		_ = closeTransport()
		_ = device.Close()
		return nil, err
	}
	session := &Session{stack: s, closeTransport: closeTransport, terminalDone: make(chan struct{})}
	if done != nil {
		go func() {
			err := <-done
			session.terminalMu.Lock()
			session.terminalErr = err
			session.terminalMu.Unlock()
			close(session.terminalDone)
			_ = session.closeTransport()
			_ = session.stack.Close()
		}()
	}
	return session, nil
}

// Addresses returns the IP prefixes assigned to the userspace stack.
func (s *Session) Addresses() []netip.Prefix { return s.stack.Addresses() }

// DialContext opens a TCP or UDP connection through the VPN.
func (s *Session) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return s.stack.DialContext(ctx, network, address)
}

// Dial implements net.Dialer-style dialing without a context.
func (s *Session) Dial(network, address string) (net.Conn, error) {
	return s.DialContext(context.Background(), network, address)
}

// Listen opens a TCP listener inside the VPN address space.
func (s *Session) Listen(network, address string) (net.Listener, error) {
	return s.stack.Listen(network, address)
}

// ListenPacket opens a UDP socket inside the VPN address space.
func (s *Session) ListenPacket(network, address string) (net.PacketConn, error) {
	return s.stack.ListenPacket(network, address)
}

// Wait blocks until the protocol terminates, the session is closed, or ctx is
// canceled. A nil terminal error is returned for an orderly shutdown.
func (s *Session) Wait(ctx context.Context) error {
	select {
	case <-s.terminalDone:
		return s.protocolError()
	default:
	}
	select {
	case <-s.terminalDone:
		return s.protocolError()
	case <-s.stack.Done():
		select {
		case <-s.terminalDone:
			return s.protocolError()
		default:
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) protocolError() error {
	s.terminalMu.RLock()
	defer s.terminalMu.RUnlock()
	return s.terminalErr
}

// Close tears down the protocol transport and gVisor stack. It is idempotent.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		transportErr := s.closeTransport()
		stackErr := s.stack.Close()
		s.closeErr = errors.Join(transportErr, stackErr)
	})
	return s.closeErr
}
