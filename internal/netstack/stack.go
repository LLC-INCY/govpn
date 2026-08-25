package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID tcpip.NICID = 1

type packetDevice interface {
	Inject(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}

// Stack is a gVisor network stack connected to a VPN packet device.
type Stack struct {
	stack     *stack.Stack
	link      *channel.Endpoint
	device    packetDevice
	addresses []netip.Prefix

	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	addressMu sync.Mutex
	closed    bool
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup
}

func New(addresses []netip.Prefix, mtu uint32, device packetDevice) (*Stack, error) {
	if len(addresses) == 0 {
		return nil, errors.New("govpn: userspace stack requires at least one address")
	}
	if device == nil {
		return nil, errors.New("govpn: nil packet device")
	}
	if mtu == 0 {
		mtu = 1400
	}

	ns := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6,
		},
		RawFactory: raw.EndpointFactory{},
	})
	link := channel.New(1024, mtu, "")
	if err := ns.CreateNICWithOptions(nicID, link, stack.NICOptions{DeliverLinkPackets: true}); err != nil {
		ns.Destroy()
		return nil, fmt.Errorf("govpn: create gVisor NIC: %s", err)
	}

	clean := make([]netip.Prefix, 0, len(addresses))
	has4, has6 := false, false
	for _, prefix := range addresses {
		if !prefix.IsValid() {
			ns.Destroy()
			return nil, errors.New("govpn: invalid userspace address")
		}
		originalAddr := prefix.Addr().Unmap()
		protocol, tcpAddr := protocolAddress(originalAddr, prefix.Bits())
		if err := ns.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          protocol,
			AddressWithPrefix: tcpAddr,
		}, stack.AddressProperties{}); err != nil {
			ns.Destroy()
			return nil, fmt.Errorf("govpn: add gVisor address %s: %s", prefix, err)
		}
		clean = append(clean, netip.PrefixFrom(originalAddr, prefix.Bits()))
		has4 = has4 || originalAddr.Is4()
		has6 = has6 || originalAddr.Is6()
	}
	routes := make([]tcpip.Route, 0, 2)
	if has4 {
		routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	}
	if has6 {
		routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	}
	ns.SetRouteTable(routes)

	ctx, cancel := context.WithCancel(context.Background())
	s := &Stack{stack: ns, link: link, device: device, addresses: clean, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	s.wg.Add(2)
	go s.outboundLoop()
	go s.inboundLoop()
	return s, nil
}

func (s *Stack) Addresses() []netip.Prefix {
	s.addressMu.Lock()
	defer s.addressMu.Unlock()
	return append([]netip.Prefix(nil), s.addresses...)
}

func (s *Stack) Done() <-chan struct{} { return s.done }

// AddAddress adds an address that can receive packets in the userspace stack.
// It does not change host networking.
func (s *Stack) AddAddress(prefix netip.Prefix) error {
	if !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return errors.New("govpn: invalid userspace address")
	}
	prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits())
	protocol, address := protocolAddress(prefix.Addr(), prefix.Bits())
	s.addressMu.Lock()
	defer s.addressMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	for _, existing := range s.addresses {
		if existing == prefix {
			return nil
		}
	}
	if err := s.stack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          protocol,
		AddressWithPrefix: address,
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("govpn: add userspace address %s: %s", prefix, err)
	}
	s.addresses = append(s.addresses, prefix)
	return nil
}

// RemoveAddress removes an address previously added to the userspace stack.
// It does not change host networking.
func (s *Stack) RemoveAddress(prefix netip.Prefix) error {
	if !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return errors.New("govpn: invalid userspace address")
	}
	prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits())
	_, address := protocolAddress(prefix.Addr(), prefix.Bits())
	s.addressMu.Lock()
	defer s.addressMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	index := -1
	for i, existing := range s.addresses {
		if existing == prefix {
			index = i
			break
		}
	}
	if index < 0 {
		return nil
	}
	if err := s.stack.RemoveAddress(nicID, address.Address); err != nil {
		return fmt.Errorf("govpn: remove userspace address %s: %s", prefix, err)
	}
	s.addresses = append(s.addresses[:index], s.addresses[index+1:]...)
	return nil
}

func (s *Stack) Close() error {
	s.closeOnce.Do(func() {
		s.addressMu.Lock()
		s.closed = true
		s.addressMu.Unlock()
		s.cancel()
		s.link.Close()
		deviceErr := s.device.Close()
		s.wg.Wait()
		s.stack.Destroy()
		close(s.done)
		s.closeErr = deviceErr
	})
	return s.closeErr
}
