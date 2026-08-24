package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

func protocolAddress(addr netip.Addr, bits int) (tcpip.NetworkProtocolNumber, tcpip.AddressWithPrefix) {
	if addr.Is4() {
		a := addr.As4()
		return ipv4.ProtocolNumber, tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4(a), PrefixLen: bits}
	}
	a := addr.As16()
	return ipv6.ProtocolNumber, tcpip.AddressWithPrefix{Address: tcpip.AddrFrom16(a), PrefixLen: bits}
}

func parseAddress(ctx context.Context, network, address string, allowEmptyHost bool) (tcpip.Address, uint16, tcpip.NetworkProtocolNumber, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return tcpip.Address{}, 0, 0, err
	}
	port64, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return tcpip.Address{}, 0, 0, fmt.Errorf("govpn: invalid port %q: %w", portText, err)
	}
	if host == "" && allowEmptyHost {
		if strings.HasSuffix(network, "6") {
			return tcpip.Address{}, uint16(port64), ipv6.ProtocolNumber, nil
		}
		return tcpip.Address{}, uint16(port64), ipv4.ProtocolNumber, nil
	}
	addr, err := resolveAddr(ctx, network, host)
	if err != nil {
		return tcpip.Address{}, 0, 0, err
	}
	protocol, withPrefix := protocolAddress(addr, addr.BitLen())
	return withPrefix.Address, uint16(port64), protocol, nil
}

func resolveAddr(ctx context.Context, network, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap(), nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addrs {
		addr = addr.Unmap()
		if strings.HasSuffix(network, "4") && !addr.Is4() {
			continue
		}
		if strings.HasSuffix(network, "6") && !addr.Is6() {
			continue
		}
		return addr, nil
	}
	return netip.Addr{}, fmt.Errorf("govpn: no address for %q matching %s", host, network)
}

func baseNetwork(network string) string {
	return strings.TrimSuffix(strings.TrimSuffix(network, "4"), "6")
}
