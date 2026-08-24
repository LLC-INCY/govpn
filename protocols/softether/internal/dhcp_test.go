package softether

import (
	"net/netip"
	"testing"
)

func TestDHCPClientServerExchange(t *testing.T) {
	clientMAC := [6]byte{0x02, 0, 0, 0, 0, 2}
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 1}
	serverIP := netip.MustParseAddr("10.40.0.1")
	assigned := netip.MustParseAddr("10.40.0.2")
	dns := []netip.Addr{netip.MustParseAddr("10.40.0.53")}
	const xid = 0x12345678

	discover := buildDHCPClient(dhcpDiscover, xid, clientMAC, netip.Addr{}, netip.Addr{})
	offerFrame, learnedIP, learnedMAC, ok := DHCPServerReply(discover, serverMAC, serverIP, assigned, 24, dns)
	if !ok || learnedIP != assigned || learnedMAC != clientMAC {
		t.Fatalf("DHCP discover = %v, %v, %x", ok, learnedIP, learnedMAC)
	}
	offer, ok := parseDHCP(offerFrame)
	if !ok || offer.messageType != dhcpOffer || offer.yourIP != assigned || offer.serverIP != serverIP {
		t.Fatalf("DHCP offer = %+v, %v", offer, ok)
	}

	request := buildDHCPClient(dhcpRequest, xid, clientMAC, assigned, serverIP)
	ackFrame, _, _, ok := DHCPServerReply(request, serverMAC, serverIP, assigned, 24, dns)
	if !ok {
		t.Fatal("DHCP request was not handled")
	}
	ack, ok := parseDHCP(ackFrame)
	if !ok || ack.messageType != dhcpACK || maskBits(ack.subnetMask) != 24 || ack.router != serverIP || len(ack.dns) != 1 || ack.dns[0] != dns[0] {
		t.Fatalf("DHCP ACK = %+v, %v", ack, ok)
	}
}

func TestDHCPRejectsDifferentRequestedAddress(t *testing.T) {
	clientMAC := [6]byte{0x02, 0, 0, 0, 0, 2}
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 1}
	serverIP := netip.MustParseAddr("10.40.0.1")
	assigned := netip.MustParseAddr("10.40.0.2")
	request := buildDHCPClient(dhcpRequest, 1, clientMAC, netip.MustParseAddr("10.40.0.99"), serverIP)
	frame, _, _, ok := DHCPServerReply(request, serverMAC, serverIP, assigned, 24, nil)
	packet, parsed := parseDHCP(frame)
	if !ok || !parsed || packet.messageType != dhcpNAK {
		t.Fatalf("DHCP NAK = %+v, handled=%v parsed=%v", packet, ok, parsed)
	}
}
