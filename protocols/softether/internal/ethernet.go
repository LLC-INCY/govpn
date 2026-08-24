package softether

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
)

func ResolveARP(stream *FrameStream, localMAC [6]byte, localIP, targetIP netip.Addr) ([6]byte, error) {
	var zero [6]byte
	if !localIP.Is4() || !targetIP.Is4() {
		return zero, errors.New("softether: ARP requires IPv4 addresses")
	}
	if err := stream.WriteFrames(ARPRequest(localMAC, localIP, targetIP)); err != nil {
		return zero, err
	}
	for {
		frames, err := stream.ReadFrames()
		if err != nil {
			return zero, err
		}
		for _, frame := range frames {
			if mac, ok := parseARPReply(frame, localMAC, localIP, targetIP); ok {
				return mac, nil
			}
		}
	}
}

func ARPRequest(localMAC [6]byte, localIP, targetIP netip.Addr) []byte {
	frame := make([]byte, 42)
	for i := range 6 {
		frame[i] = 0xff
	}
	copy(frame[6:12], localMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], 1)
	copy(arp[8:14], localMAC[:])
	copy(arp[14:18], localIP.AsSlice())
	copy(arp[24:28], targetIP.AsSlice())
	return frame
}

func parseARPReply(frame []byte, localMAC [6]byte, localIP, targetIP netip.Addr) ([6]byte, bool) {
	var sourceMAC [6]byte
	if len(frame) < 42 || binary.BigEndian.Uint16(frame[12:14]) != 0x0806 {
		return sourceMAC, false
	}
	arp := frame[14:]
	if binary.BigEndian.Uint16(arp[0:2]) != 1 || binary.BigEndian.Uint16(arp[2:4]) != 0x0800 ||
		arp[4] != 6 || arp[5] != 4 || binary.BigEndian.Uint16(arp[6:8]) != 2 ||
		!bytes.Equal(arp[14:18], targetIP.AsSlice()) || !bytes.Equal(arp[18:24], localMAC[:]) ||
		!bytes.Equal(arp[24:28], localIP.AsSlice()) {
		return sourceMAC, false
	}
	copy(sourceMAC[:], arp[8:14])
	return sourceMAC, true
}

func WrapIPv4(payload []byte, source, destination [6]byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[:6], destination[:])
	copy(frame[6:12], source[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:], payload)
	return frame
}

func UnwrapIP(frame []byte) ([]byte, bool) {
	if len(frame) < 14 {
		return nil, false
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != 0x0800 && etherType != 0x86dd {
		return nil, false
	}
	return append([]byte(nil), frame[14:]...), true
}

func IPDestination(packet []byte) (netip.Addr, bool) {
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		return netip.AddrFrom4([4]byte(packet[16:20])), true
	}
	if len(packet) >= 40 && packet[0]>>4 == 6 {
		return netip.AddrFrom16([16]byte(packet[24:40])), true
	}
	return netip.Addr{}, false
}

func FrameSource(frame []byte) (netip.Addr, [6]byte, bool) {
	var mac [6]byte
	if len(frame) < 14 {
		return netip.Addr{}, mac, false
	}
	copy(mac[:], frame[6:12])
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0800:
		if len(frame) >= 34 && frame[14]>>4 == 4 {
			return netip.AddrFrom4([4]byte(frame[26:30])), mac, true
		}
	case 0x86dd:
		if len(frame) >= 54 && frame[14]>>4 == 6 {
			return netip.AddrFrom16([16]byte(frame[22:38])), mac, true
		}
	case 0x0806:
		if len(frame) >= 42 {
			arp := frame[14:]
			if binary.BigEndian.Uint16(arp[0:2]) == 1 && binary.BigEndian.Uint16(arp[2:4]) == 0x0800 && arp[4] == 6 && arp[5] == 4 {
				copy(mac[:], arp[8:14])
				return netip.AddrFrom4([4]byte(arp[14:18])), mac, true
			}
		}
	}
	return netip.Addr{}, mac, false
}

func ARPReply(frame []byte, localMAC [6]byte, localIP netip.Addr) ([]byte, bool) {
	if len(frame) < 42 || !localIP.Is4() || binary.BigEndian.Uint16(frame[12:14]) != 0x0806 {
		return nil, false
	}
	arp := frame[14:]
	if binary.BigEndian.Uint16(arp[0:2]) != 1 ||
		binary.BigEndian.Uint16(arp[2:4]) != 0x0800 ||
		arp[4] != 6 || arp[5] != 4 ||
		binary.BigEndian.Uint16(arp[6:8]) != 1 {
		return nil, false
	}
	targetIP := localIP.As4()
	if !bytes.Equal(arp[24:28], targetIP[:]) {
		return nil, false
	}
	reply := make([]byte, 42)
	copy(reply[0:6], arp[8:14])
	copy(reply[6:12], localMAC[:])
	binary.BigEndian.PutUint16(reply[12:14], 0x0806)
	replyARP := reply[14:]
	binary.BigEndian.PutUint16(replyARP[0:2], 1)
	binary.BigEndian.PutUint16(replyARP[2:4], 0x0800)
	replyARP[4], replyARP[5] = 6, 4
	binary.BigEndian.PutUint16(replyARP[6:8], 2)
	copy(replyARP[8:14], localMAC[:])
	copy(replyARP[14:18], targetIP[:])
	copy(replyARP[18:24], arp[8:14])
	copy(replyARP[24:28], arp[14:18])
	return reply, true
}
