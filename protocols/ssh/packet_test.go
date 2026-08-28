package ssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestReadIPPacketPreservesPacketBoundaries(t *testing.T) {
	ipv4 := makeIPv4Packet([]byte{1, 2, 3, 4})
	ipv6 := makeIPv6Packet([]byte{5, 6, 7, 8})
	reader := bytes.NewReader(append(ipv4, ipv6...))

	gotIPv4, err := readIPPacket(reader, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotIPv4, ipv4) {
		t.Fatalf("IPv4 packet = %x, want %x", gotIPv4, ipv4)
	}

	gotIPv6, err := readIPPacket(reader, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotIPv6, ipv6) {
		t.Fatalf("IPv6 packet = %x, want %x", gotIPv6, ipv6)
	}
}

func TestReadIPPacketAcceptsEmptyIPv6Payload(t *testing.T) {
	packet := makeIPv6Packet(nil)
	got, err := readIPPacket(bytes.NewReader(packet), 1280)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, packet) {
		t.Fatalf("packet = %x, want %x", got, packet)
	}
}

func TestReadIPPacketRejectsInvalidPackets(t *testing.T) {
	overMTU := makeIPv4Packet(make([]byte, 100))
	tests := []struct {
		name   string
		packet []byte
		mtu    int
	}{
		{name: "unknown version", packet: []byte{0x70, 0, 0, 4}, mtu: 1500},
		{name: "short IPv4 header", packet: []byte{0x44, 0, 0, 16}, mtu: 1500},
		{name: "IPv4 length below header", packet: []byte{0x45, 0, 0, 19}, mtu: 1500},
		{name: "over MTU", packet: overMTU, mtu: 100},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := readIPPacket(bytes.NewReader(test.packet), test.mtu); err == nil {
				t.Fatal("readIPPacket succeeded")
			}
		})
	}
}

func TestReadIPPacketReportsTruncation(t *testing.T) {
	packet := makeIPv6Packet([]byte{1, 2, 3, 4})
	_, err := readIPPacket(bytes.NewReader(packet[:len(packet)-1]), 1500)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want io.ErrUnexpectedEOF", err)
	}
}

func makeIPv4Packet(payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[20:], payload)
	return packet
}

func makeIPv6Packet(payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	copy(packet[40:], payload)
	return packet
}
