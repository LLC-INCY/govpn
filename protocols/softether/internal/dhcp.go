package softether

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpACK      = 5
	dhcpNAK      = 6

	dhcpMinimumMessageSize = 300
)

var dhcpCookie = [4]byte{99, 130, 83, 99}

type DHCPLease struct {
	Address   netip.Prefix
	Gateway   netip.Addr
	DNS       []netip.Addr
	ServerMAC [6]byte
}

type dhcpPacket struct {
	messageType byte
	xid         uint32
	clientMAC   [6]byte
	yourIP      netip.Addr
	requestedIP netip.Addr
	serverIP    netip.Addr
	subnetMask  netip.Addr
	router      netip.Addr
	dns         []netip.Addr
	sourceMAC   [6]byte
}

func AcquireDHCP(stream *FrameStream, mac [6]byte) (DHCPLease, error) {
	var xidBytes [4]byte
	if _, err := rand.Read(xidBytes[:]); err != nil {
		return DHCPLease{}, fmt.Errorf("softether: DHCP transaction ID: %w", err)
	}
	xid := binary.BigEndian.Uint32(xidBytes[:])
	if err := stream.WriteFrames(buildDHCPClient(dhcpDiscover, xid, mac, netip.Addr{}, netip.Addr{})); err != nil {
		return DHCPLease{}, err
	}
	offer, err := readDHCP(stream, xid, mac, dhcpOffer)
	if err != nil {
		return DHCPLease{}, fmt.Errorf("softether: DHCP offer: %w", err)
	}
	if !offer.yourIP.Is4() || !offer.serverIP.Is4() {
		return DHCPLease{}, errors.New("softether: DHCP offer is missing an address or server identifier")
	}
	if err := stream.WriteFrames(buildDHCPClient(dhcpRequest, xid, mac, offer.yourIP, offer.serverIP)); err != nil {
		return DHCPLease{}, err
	}
	ack, err := readDHCP(stream, xid, mac, dhcpACK)
	if err != nil {
		return DHCPLease{}, fmt.Errorf("softether: DHCP acknowledgement: %w", err)
	}
	if !ack.yourIP.Is4() || ack.yourIP.IsUnspecified() {
		return DHCPLease{}, errors.New("softether: DHCP acknowledgement has no assigned IPv4 address")
	}
	bits := maskBits(ack.subnetMask)
	if bits < 0 {
		bits = 24
	}
	gateway := ack.router
	if !gateway.Is4() {
		gateway = ack.serverIP
	}
	return DHCPLease{
		Address: netip.PrefixFrom(ack.yourIP, bits), Gateway: gateway,
		DNS: append([]netip.Addr(nil), ack.dns...), ServerMAC: ack.sourceMAC,
	}, nil
}

func readDHCP(stream *FrameStream, xid uint32, mac [6]byte, wanted byte) (dhcpPacket, error) {
	for {
		frames, err := stream.ReadFrames()
		if err != nil {
			return dhcpPacket{}, err
		}
		for _, frame := range frames {
			packet, ok := parseDHCP(frame)
			if !ok || packet.xid != xid || packet.clientMAC != mac {
				continue
			}
			if packet.messageType == dhcpNAK {
				return dhcpPacket{}, errors.New("server returned DHCP NAK")
			}
			if packet.messageType == wanted {
				return packet, nil
			}
		}
	}
}

func DHCPServerReply(frame []byte, serverMAC [6]byte, serverIP, assigned netip.Addr, prefixBits int, dns []netip.Addr) ([]byte, netip.Addr, [6]byte, bool) {
	request, ok := parseDHCP(frame)
	if !ok || !serverIP.Is4() || !assigned.Is4() {
		return nil, netip.Addr{}, [6]byte{}, false
	}
	var responseType byte
	switch request.messageType {
	case dhcpDiscover:
		responseType = dhcpOffer
	case dhcpRequest:
		if request.requestedIP.IsValid() && request.requestedIP != assigned {
			responseType = dhcpNAK
		} else {
			responseType = dhcpACK
		}
	default:
		return nil, netip.Addr{}, [6]byte{}, false
	}
	return buildDHCPServer(responseType, request.xid, request.clientMAC, serverMAC, serverIP, assigned, prefixBits, dns), assigned, request.clientMAC, true
}

func buildDHCPClient(messageType byte, xid uint32, mac [6]byte, requestedIP, serverIP netip.Addr) []byte {
	bootp := make([]byte, 240)
	bootp[0], bootp[1], bootp[2] = 1, 1, 6
	binary.BigEndian.PutUint32(bootp[4:8], xid)
	binary.BigEndian.PutUint16(bootp[10:12], 0x8000)
	copy(bootp[28:34], mac[:])
	copy(bootp[236:240], dhcpCookie[:])
	options := []byte{53, 1, messageType, 61, 7, 1}
	options = append(options, mac[:]...)
	if requestedIP.Is4() {
		options = appendIPOption(options, 50, requestedIP)
	}
	if serverIP.Is4() {
		options = appendIPOption(options, 54, serverIP)
	}
	options = append(options, 55, 8, 1, 3, 6, 15, 51, 54, 58, 59, 255)
	return wrapDHCP(bootp, options, mac, [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, netip.IPv4Unspecified(), netip.MustParseAddr("255.255.255.255"), 68, 67)
}

func buildDHCPServer(messageType byte, xid uint32, clientMAC, serverMAC [6]byte, serverIP, assigned netip.Addr, prefixBits int, dns []netip.Addr) []byte {
	bootp := make([]byte, 240)
	bootp[0], bootp[1], bootp[2] = 2, 1, 6
	binary.BigEndian.PutUint32(bootp[4:8], xid)
	binary.BigEndian.PutUint16(bootp[10:12], 0x8000)
	if messageType != dhcpNAK {
		copy(bootp[16:20], assigned.AsSlice())
	}
	copy(bootp[20:24], serverIP.AsSlice())
	copy(bootp[28:34], clientMAC[:])
	copy(bootp[236:240], dhcpCookie[:])
	options := []byte{53, 1, messageType}
	options = appendIPOption(options, 54, serverIP)
	if messageType != dhcpNAK {
		mask := prefixMask(prefixBits)
		options = append(options, 1, 4)
		options = append(options, mask[:]...)
		options = appendIPOption(options, 3, serverIP)
		options = append(options, 51, 4, 0, 0, 0x0e, 0x10)
		options = append(options, 58, 4, 0, 0, 0x07, 0x08)
		options = append(options, 59, 4, 0, 0, 0x0c, 0x4e)
		for _, address := range dns {
			if address.Is4() {
				options = appendIPOption(options, 6, address)
				break
			}
		}
	}
	options = append(options, 255)
	return wrapDHCP(bootp, options, serverMAC, [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, serverIP, netip.MustParseAddr("255.255.255.255"), 67, 68)
}

func wrapDHCP(bootp, options []byte, sourceMAC, destinationMAC [6]byte, sourceIP, destinationIP netip.Addr, sourcePort, destinationPort uint16) []byte {
	payloadLength := max(len(bootp)+len(options), dhcpMinimumMessageSize)
	frame := make([]byte, 14+20+8+payloadLength)
	copy(frame[0:6], destinationMAC[:])
	copy(frame[6:12], sourceMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+payloadLength))
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	copy(ip[12:16], sourceIP.AsSlice())
	copy(ip[16:20], destinationIP.AsSlice())
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+payloadLength))
	copy(frame[42:42+len(bootp)], bootp)
	copy(frame[42+len(bootp):], options)
	return frame
}

func parseDHCP(frame []byte) (dhcpPacket, bool) {
	var packet dhcpPacket
	if len(frame) < 14+20+8+240 || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return packet, false
	}
	copy(packet.sourceMAC[:], frame[6:12])
	ip := frame[14:]
	if ip[0]>>4 != 4 || ip[9] != 17 {
		return packet, false
	}
	headerLength := int(ip[0]&0x0f) * 4
	if headerLength < 20 || len(ip) < headerLength+8+240 {
		return packet, false
	}
	udp := ip[headerLength:]
	sourcePort, destinationPort := binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4])
	if !((sourcePort == 67 && destinationPort == 68) || (sourcePort == 68 && destinationPort == 67)) {
		return packet, false
	}
	udpLength := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLength < 8+240 || udpLength > len(udp) {
		return packet, false
	}
	bootp := udp[8:udpLength]
	if !equal4(bootp[236:240], dhcpCookie) {
		return packet, false
	}
	packet.xid = binary.BigEndian.Uint32(bootp[4:8])
	copy(packet.clientMAC[:], bootp[28:34])
	packet.yourIP = addr4(bootp[16:20])
	options := parseDHCPOptions(bootp[240:])
	if value := options[53]; len(value) == 1 {
		packet.messageType = value[0]
	} else {
		return packet, false
	}
	packet.requestedIP = optionAddr(options[50])
	packet.serverIP = optionAddr(options[54])
	packet.subnetMask = optionAddr(options[1])
	packet.router = firstOptionAddr(options[3])
	for data := options[6]; len(data) >= 4; data = data[4:] {
		packet.dns = append(packet.dns, addr4(data[:4]))
	}
	return packet, true
}

func parseDHCPOptions(data []byte) map[byte][]byte {
	options := make(map[byte][]byte)
	for len(data) != 0 {
		code := data[0]
		data = data[1:]
		if code == 0 {
			continue
		}
		if code == 255 || len(data) == 0 {
			break
		}
		length := int(data[0])
		data = data[1:]
		if length > len(data) {
			break
		}
		options[code] = append(options[code], data[:length]...)
		data = data[length:]
	}
	return options
}

func appendIPOption(options []byte, code byte, address netip.Addr) []byte {
	value := address.As4()
	options = append(options, code, 4)
	return append(options, value[:]...)
}

func optionAddr(value []byte) netip.Addr {
	if len(value) != 4 {
		return netip.Addr{}
	}
	return addr4(value)
}

func firstOptionAddr(value []byte) netip.Addr {
	if len(value) < 4 {
		return netip.Addr{}
	}
	return addr4(value[:4])
}

func addr4(value []byte) netip.Addr {
	return netip.AddrFrom4([4]byte(value[:4]))
}

func equal4(value []byte, expected [4]byte) bool {
	return len(value) == 4 && [4]byte(value) == expected
}

func prefixMask(bits int) [4]byte {
	var mask [4]byte
	if bits < 0 || bits > 32 {
		return mask
	}
	value := ^uint32(0)
	if bits == 0 {
		value = 0
	} else {
		value <<= 32 - bits
	}
	binary.BigEndian.PutUint32(mask[:], value)
	return mask
}

func maskBits(mask netip.Addr) int {
	if !mask.Is4() {
		return -1
	}
	value := binary.BigEndian.Uint32(mask.AsSlice())
	bits := 0
	seenZero := false
	for i := 31; i >= 0; i-- {
		set := value&(1<<i) != 0
		if set && seenZero {
			return -1
		}
		if set {
			bits++
		} else {
			seenZero = true
		}
	}
	return bits
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
