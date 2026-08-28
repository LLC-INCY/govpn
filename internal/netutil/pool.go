// Package netutil contains protocol-independent network address helpers.
package netutil

import (
	"errors"
	"fmt"
	"net/netip"
)

// ParseIPv4Pool parses an IPv4 prefix whose first two host addresses are used
// as the server gateway and the first client address.
func ParseIPv4Pool(value string) (network netip.Prefix, gateway, client netip.Addr, err error) {
	return parsePool(value, false)
}

// ParseIPv6Pool is the IPv6 counterpart of ParseIPv4Pool.
func ParseIPv6Pool(value string) (network netip.Prefix, gateway, client netip.Addr, err error) {
	return parsePool(value, true)
}

func parsePool(value string, ipv6 bool) (network netip.Prefix, gateway, client netip.Addr, err error) {
	network, err = netip.ParsePrefix(value)
	validFamily := network.Addr().Is4()
	family, maximumBits := "IPv4", 30
	if ipv6 {
		validFamily = network.Addr().Is6()
		family, maximumBits = "IPv6", 126
	}
	if err != nil || !validFamily {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid %s pool %q", family, value)
	}
	network = network.Masked()
	if network.Bits() > maximumBits {
		poolName := "pool"
		if ipv6 {
			poolName = "IPv6 pool"
		}
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, errors.New(poolName + " has fewer than two usable addresses")
	}
	gateway = network.Addr().Next()
	return network, gateway, gateway.Next(), nil
}
