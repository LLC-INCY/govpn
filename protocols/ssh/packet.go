package ssh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

func readIPPacket(reader io.Reader, mtu int) ([]byte, error) {
	prefix := make([]byte, 4)
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return nil, err
	}
	var total int
	switch prefix[0] >> 4 {
	case 4:
		headerLength := int(prefix[0]&0x0f) * 4
		total = int(binary.BigEndian.Uint16(prefix[2:4]))
		if headerLength < 20 || total < headerLength {
			return nil, errors.New("ssh: invalid IPv4 packet from TUN channel")
		}
	case 6:
		header := make([]byte, 2)
		if _, err := io.ReadFull(reader, header); err != nil {
			return nil, err
		}
		prefix = append(prefix, header...)
		payloadLength := int(binary.BigEndian.Uint16(prefix[4:6]))
		total = 40 + payloadLength
	default:
		return nil, fmt.Errorf("ssh: unsupported IP version %d from TUN channel", prefix[0]>>4)
	}
	if total > mtu {
		return nil, fmt.Errorf("ssh: inbound IP packet length %d exceeds MTU %d", total, mtu)
	}
	packet := make([]byte, total)
	copy(packet, prefix)
	if _, err := io.ReadFull(reader, packet[len(prefix):]); err != nil {
		return nil, err
	}
	return packet, nil
}
