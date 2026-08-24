package sstp

import (
	"bytes"
	"net"
	"testing"
	"time"

	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

func TestClientLCPStartsPPPAndNegotiatesPAP(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	clientFramer := protocol.NewFramer(clientConn, clientConn)
	serverFramer := protocol.NewFramer(serverConn, serverConn)
	done := make(chan error, 1)
	go func() { done <- negotiateClientLCP(clientFramer, func(string, ...any) {}) }()

	clientRequest := readTestPPP(t, serverFramer)
	clientLCP, err := protocol.ExpectControl(clientRequest, protocol.PPPLCP, protocol.ConfigureRequest)
	if err != nil {
		t.Fatal(err)
	}
	chapOptions := []byte{protocol.LCPOptionAuthentication, 5, 0xc2, 0x23, protocol.CHAPAlgorithmMSCHAPv2}
	writeTestPPP(t, serverFramer, protocol.ConfigureRequest, 9, chapOptions)
	nak := readTestPPP(t, serverFramer)
	nakControl, err := protocol.ExpectControl(nak, protocol.PPPLCP, protocol.ConfigureNak)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nakControl.Payload, protocol.PAPAuthenticationOption()) {
		t.Fatalf("LCP NAK = %x", nakControl.Payload)
	}

	writeTestPPP(t, serverFramer, protocol.ConfigureAck, clientLCP.ID, clientLCP.Payload)
	writeTestPPP(t, serverFramer, protocol.ConfigureRequest, 10, protocol.PAPAuthenticationOption())
	ack := readTestPPP(t, serverFramer)
	ackControl, err := protocol.ExpectControl(ack, protocol.PPPLCP, protocol.ConfigureAck)
	if err != nil {
		t.Fatal(err)
	}
	if ackControl.ID != 10 || !bytes.Equal(ackControl.Payload, protocol.PAPAuthenticationOption()) {
		t.Fatalf("LCP ACK = %+v", ackControl)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func readTestPPP(t *testing.T, framer *protocol.Framer) protocol.PPPFrame {
	t.Helper()
	packet, err := framer.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if packet.Control {
		t.Fatalf("got SSTP control message %d", packet.Message)
	}
	frame, err := protocol.DecodePPP(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func writeTestPPP(t *testing.T, framer *protocol.Framer, code, id byte, options []byte) {
	t.Helper()
	if err := framer.WriteData(protocol.EncodePPP(protocol.PPPLCP, protocol.EncodeControl(code, id, options))); err != nil {
		t.Fatal(err)
	}
}
