package sstp

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestPPPFrameVector(t *testing.T) {
	payload := EncodeControl(ConfigureRequest, 7, IPv4Option(netip.MustParseAddr("10.0.0.2")))
	frame := EncodePPP(PPPIPCP, payload)
	want := []byte{0xff, 0x03, 0x80, 0x21, 1, 7, 0, 10, 3, 6, 10, 0, 0, 2}
	if !bytes.Equal(frame, want) {
		t.Fatalf("frame = %x, want %x", frame, want)
	}
	decoded, err := DecodePPP(frame)
	if err != nil {
		t.Fatal(err)
	}
	control, err := ExpectControl(decoded, PPPIPCP, ConfigureRequest)
	if err != nil {
		t.Fatal(err)
	}
	if address, ok := ParseIPv4Option(control.Payload); !ok || address.String() != "10.0.0.2" {
		t.Fatalf("address = %s, %v", address, ok)
	}
}

func TestPAPRoundTrip(t *testing.T) {
	request, err := EncodePAPRequest(9, "alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	id, username, password, err := DecodePAPRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if id != 9 || username != "alice" || password != "secret" {
		t.Fatalf("decoded = %d %q %q", id, username, password)
	}
}

func TestParseLCPAuthentication(t *testing.T) {
	options := append([]byte{LCPOptionMRU, 4, 0x05, 0xdc}, []byte{LCPOptionAuthentication, 5, 0xc2, 0x23, CHAPAlgorithmMSCHAPv2}...)
	authentication, algorithm, found, err := ParseLCPAuthentication(options)
	if err != nil {
		t.Fatal(err)
	}
	if !found || authentication != PPPCHAP || !bytes.Equal(algorithm, []byte{CHAPAlgorithmMSCHAPv2}) {
		t.Fatalf("authentication = %#x, algorithm = %x, found = %t", authentication, algorithm, found)
	}
	if !bytes.Equal(PAPAuthenticationOption(), []byte{3, 4, 0xc0, 0x23}) {
		t.Fatalf("PAP option = %x", PAPAuthenticationOption())
	}
}

func TestParseLCPAuthenticationRejectsMalformedOption(t *testing.T) {
	if _, _, _, err := ParseLCPAuthentication([]byte{LCPOptionAuthentication, 5, 0xc2}); err == nil {
		t.Fatal("malformed LCP option was accepted")
	}
}
