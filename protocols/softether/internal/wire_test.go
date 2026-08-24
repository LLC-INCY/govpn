package softether

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"testing"
)

func TestReadSignatureRequest(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want bool
	}{
		{name: "legacy", body: []byte("VPNCONNECT"), want: true},
		{name: "forged watermark prefix", body: append(append([]byte(nil), officialWatermarkPrefix...), bytes.Repeat([]byte{0x5a}, officialWatermarkSize)...), want: false},
		{name: "invalid", body: []byte("not-softether"), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: vpn.example\r\nContent-Length: %d\r\n\r\n", ConnectPath, len(test.body))
			reader := bufio.NewReader(io.MultiReader(bytes.NewBufferString(request), bytes.NewReader(test.body)))
			err := ReadSignatureRequest(reader)
			if (err == nil) != test.want {
				t.Fatalf("ReadSignatureRequest() error = %v, want success %v", err, test.want)
			}
		})
	}
}

func TestCompressedFrameStream(t *testing.T) {
	var wire bytes.Buffer
	stream := NewFrameStream(&wire, &wire, true)
	frame := bytes.Repeat([]byte{0x5a}, 512)
	if err := stream.WriteFrames(frame); err != nil {
		t.Fatal(err)
	}
	frames, err := stream.ReadFrames()
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || !bytes.Equal(frames[0], frame) {
		t.Fatalf("compressed frame round-trip = %d frames", len(frames))
	}
}

func TestFrameStreamAndEthernet(t *testing.T) {
	var wire bytes.Buffer
	stream := NewFrameStream(&wire, &wire)
	ip := []byte{0x45, 0, 0, 20}
	frame := WrapIPv4(ip, [6]byte{2}, [6]byte{4})
	if err := stream.WriteFrames(frame); err != nil {
		t.Fatal(err)
	}
	frames, err := stream.ReadFrames()
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := UnwrapIP(frames[0])
	if !ok || !bytes.Equal(payload, ip) {
		t.Fatalf("payload = %x, %v", payload, ok)
	}
}

func TestARPReply(t *testing.T) {
	requesterMAC := [6]byte{0x02, 0, 0, 0, 0, 2}
	localMAC := [6]byte{0x02, 0, 0, 0, 0, 1}
	request := make([]byte, 42)
	for i := range 6 {
		request[i] = 0xff
	}
	copy(request[6:12], requesterMAC[:])
	binary.BigEndian.PutUint16(request[12:14], 0x0806)
	binary.BigEndian.PutUint16(request[14:16], 1)
	binary.BigEndian.PutUint16(request[16:18], 0x0800)
	request[18], request[19] = 6, 4
	binary.BigEndian.PutUint16(request[20:22], 1)
	copy(request[22:28], requesterMAC[:])
	copy(request[28:32], netip.MustParseAddr("10.40.0.2").AsSlice())
	copy(request[38:42], netip.MustParseAddr("10.40.0.1").AsSlice())

	reply, ok := ARPReply(request, localMAC, netip.MustParseAddr("10.40.0.1"))
	if !ok {
		t.Fatal("ARPReply rejected request for local address")
	}
	if !bytes.Equal(reply[0:6], requesterMAC[:]) || !bytes.Equal(reply[6:12], localMAC[:]) {
		t.Fatalf("Ethernet addresses = %x -> %x", reply[6:12], reply[0:6])
	}
	if opcode := binary.BigEndian.Uint16(reply[20:22]); opcode != 2 {
		t.Fatalf("ARP opcode = %d", opcode)
	}
	if got := netip.AddrFrom4([4]byte(reply[28:32])); got.String() != "10.40.0.1" {
		t.Fatalf("sender IP = %v", got)
	}
	if got := netip.AddrFrom4([4]byte(reply[38:42])); got.String() != "10.40.0.2" {
		t.Fatalf("target IP = %v", got)
	}
}

func TestIPAndEthernetAddressMapping(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x45
	copy(packet[12:16], netip.MustParseAddr("10.40.0.1").AsSlice())
	copy(packet[16:20], netip.MustParseAddr("10.40.0.2").AsSlice())
	destination, ok := IPDestination(packet)
	if !ok || destination.String() != "10.40.0.2" {
		t.Fatalf("destination = %v, %v", destination, ok)
	}

	mac := [6]byte{0x02, 0, 0, 0, 0, 2}
	frame := WrapIPv4(packet, mac, [6]byte{})
	source, sourceMAC, ok := FrameSource(frame)
	if !ok || source.String() != "10.40.0.1" || sourceMAC != mac {
		t.Fatalf("source = %v, MAC = %x, valid = %v", source, sourceMAC, ok)
	}
}
