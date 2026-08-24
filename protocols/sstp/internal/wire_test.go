package sstp

import (
	"bytes"
	"testing"
)

func TestCallConnectRequestVector(t *testing.T) {
	want := []byte{0x10, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01}
	var encoded bytes.Buffer
	framer := NewFramer(bytes.NewReader(nil), &encoded)
	if err := framer.WriteControl(CallConnectRequest, Attribute{ID: AttrEncapsulatedProtocol, Value: []byte{0, ProtocolPPP}}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded.Bytes(), want) {
		t.Fatalf("encoded = %x, want %x", encoded.Bytes(), want)
	}
	decoded, err := NewFramer(bytes.NewReader(want), &bytes.Buffer{}).ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Message != CallConnectRequest || len(decoded.Attributes) != 1 || decoded.Attributes[0].ID != AttrEncapsulatedProtocol {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestFramerRejectsMalformedLength(t *testing.T) {
	for _, input := range [][]byte{
		{0x10, 0, 0, 3},
		{0x10, 1, 0, 8, 0, 1, 0, 1},
		{0x10, 1, 0, 12, 0, 1, 0, 1, 0, 1, 0, 3},
	} {
		if _, err := NewFramer(bytes.NewReader(input), &bytes.Buffer{}).ReadPacket(); err == nil {
			t.Fatalf("accepted malformed packet %x", input)
		}
	}
}
