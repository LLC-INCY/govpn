package netstack

import (
	"context"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

func (s *Stack) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, protocol, err := parseAddress(ctx, network, address, false)
	if err != nil {
		return nil, err
	}
	remote := tcpip.FullAddress{NIC: nicID, Addr: host, Port: port}
	switch baseNetwork(network) {
	case "tcp":
		return gonet.DialContextTCP(ctx, s.stack, remote, protocol)
	case "udp":
		return gonet.DialUDP(s.stack, nil, &remote, protocol)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

func (s *Stack) Listen(network, address string) (net.Listener, error) {
	if baseNetwork(network) != "tcp" {
		return nil, net.UnknownNetworkError(network)
	}
	host, port, protocol, err := parseAddress(context.Background(), network, address, true)
	if err != nil {
		return nil, err
	}
	return gonet.ListenTCP(s.stack, tcpip.FullAddress{NIC: nicID, Addr: host, Port: port}, protocol)
}

func (s *Stack) ListenPacket(network, address string) (net.PacketConn, error) {
	if baseNetwork(network) != "udp" {
		return nil, net.UnknownNetworkError(network)
	}
	host, port, protocol, err := parseAddress(context.Background(), network, address, true)
	if err != nil {
		return nil, err
	}
	local := tcpip.FullAddress{NIC: nicID, Addr: host, Port: port}
	return gonet.DialUDP(s.stack, &local, nil, protocol)
}
