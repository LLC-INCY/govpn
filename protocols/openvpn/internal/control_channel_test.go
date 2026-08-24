package openvpn

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

func TestControlChannelTLSAuthRoundTripAndReplay(t *testing.T) {
	key := testStaticKey()
	client, err := NewControlChannel(nil, ControlProtectionAuth, key, "SHA256", 1, true, false)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewControlChannel(nil, ControlProtectionAuth, key, "SHA256", 0, true, true)
	if err != nil {
		t.Fatal(err)
	}
	testControlProtectionRoundTrip(t, client, server)
}

func TestControlChannelTLSCryptRoundTripAndReplay(t *testing.T) {
	key := testStaticKey()
	client, err := NewControlChannel(nil, ControlProtectionCrypt, key, "", 0, false, false)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewControlChannel(nil, ControlProtectionCrypt, key, "", 0, false, true)
	if err != nil {
		t.Fatal(err)
	}
	testControlProtectionRoundTrip(t, client, server)
}

func TestControlChannelDoesNotWrapDataPackets(t *testing.T) {
	channel, err := NewControlChannel(nil, ControlProtectionCrypt, testStaticKey(), "", 0, false, false)
	if err != nil {
		t.Fatal(err)
	}
	packet := []byte{DataV2 << 3, 0, 0, 1, 0xaa}
	wrapped, err := channel.Wrap(packet)
	if err != nil {
		t.Fatal(err)
	}
	if string(wrapped) != string(packet) {
		t.Fatalf("data packet changed: %x", wrapped)
	}
}

func testControlProtectionRoundTrip(t *testing.T, client, server *ControlChannel) {
	t.Helper()
	plain, err := EncodeControl(Packet{Opcode: ControlHardResetClientV2, LocalSessionID: SessionID{1}, PacketID: 0})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := client.Wrap(plain)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := server.Unwrap(wire)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(plain) {
		t.Fatalf("decoded = %x, want %x", decoded, plain)
	}
	if _, err := server.Unwrap(wire); err == nil {
		t.Fatal("replayed protected control packet was accepted")
	}
}

func testStaticKey() []byte {
	value := make([]byte, 256)
	for i := range value {
		value[i] = byte(i)
	}
	return []byte("-----BEGIN OpenVPN Static key V1-----\n" + hex.EncodeToString(value) + "\n-----END OpenVPN Static key V1-----\n")
}

func TestControlChannelConnInterface(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	channel, err := NewControlChannel(left, ControlProtectionNone, nil, "", 0, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(channel.LocalAddr().Network(), "pipe") {
		t.Fatalf("unexpected address: %v", channel.LocalAddr())
	}
}
