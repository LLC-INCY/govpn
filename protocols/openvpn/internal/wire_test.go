package openvpn

import (
	"bytes"
	"testing"
)

func TestControlPacketRoundTrip(t *testing.T) {
	local := SessionID{1, 2, 3, 4, 5, 6, 7, 8}
	remote := SessionID{8, 7, 6, 5, 4, 3, 2, 1}
	want := []byte{Control << 3, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0, 0, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 10, 0xaa}
	encoded, err := EncodeControl(Packet{Opcode: Control, LocalSessionID: local, RemoteSessionID: remote, Acknowledgments: []uint32{9}, PacketID: 10, Payload: []byte{0xaa}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded = %x, want %x", encoded, want)
	}
	decoded, err := DecodeControl(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.LocalSessionID != local || decoded.RemoteSessionID != remote || decoded.PacketID != 10 || !bytes.Equal(decoded.Payload, []byte{0xaa}) {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestDataHeaders(t *testing.T) {
	header, err := DataHeader(DataV2, 3, 0x123456)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{DataV2<<3 | 3, 0x12, 0x34, 0x56}
	if !bytes.Equal(header, want) {
		t.Fatalf("header = %x, want %x", header, want)
	}
}
