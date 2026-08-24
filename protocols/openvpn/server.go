package openvpn

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
)

type Server struct{ Config ServerConfig }

func NewServer(config ServerConfig) *Server { return &Server{Config: config} }

func (s *Server) Start(ctx context.Context) (*govpn.Session, error) {
	if err := validateServer(s.Config); err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(s.Config.Cert, s.Config.Key)
	if err != nil {
		return nil, fmt.Errorf("openvpn: server certificate: %w", err)
	}
	tlsConfig, err := serverTLSConfig(s.Config, certificate)
	if err != nil {
		return nil, err
	}
	network, gateway, assigned, err := poolAddresses(s.Config.Pool)
	if err != nil {
		return nil, err
	}
	listenAddress := net.JoinHostPort(s.Config.ListenIP, strconv.Itoa(s.Config.ListenPort))
	mtu := effectiveMTU(s.Config.MTU)
	device, err := packet.New("openvpn-server", mtu)
	if err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	var closeTransport func() error
	if strings.HasPrefix(serverTransportNetwork(s.Config), "tcp") {
		listener, listenErr := net.Listen(serverTransportNetwork(s.Config), listenAddress)
		if listenErr != nil {
			_ = device.Close()
			return nil, fmt.Errorf("openvpn: TCP listen: %w", listenErr)
		}
		transport := newServerStreamTransport(listener, device, s.Config)
		closeTransport = transport.Close
		go transport.accept(tlsConfig, network, gateway, assigned, done)
	} else {
		packetConn, listenErr := net.ListenPacket(serverTransportNetwork(s.Config), listenAddress)
		if listenErr != nil {
			_ = device.Close()
			return nil, fmt.Errorf("openvpn: UDP listen: %w", listenErr)
		}
		transport := newServerTransport(packetConn, device, s.Config)
		closeTransport = transport.Close
		go transport.accept(tlsConfig, network, gateway, assigned, done)
	}
	select {
	case <-ctx.Done():
		_ = closeTransport()
		return nil, ctx.Err()
	default:
	}
	return govpn.NewSession([]netip.Prefix{netip.PrefixFrom(gateway, network.Bits())}, uint32(mtu), device, closeTransport, done)
}

func serverTransportNetwork(config ServerConfig) string {
	if config.Protocol == "" {
		return "udp"
	}
	network := strings.ToLower(config.Protocol)
	switch network {
	case "tcp-server":
		return "tcp"
	case "tcp4-server":
		return "tcp4"
	case "tcp6-server":
		return "tcp6"
	default:
		return network
	}
}
