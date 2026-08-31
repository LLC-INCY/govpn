package sstp

import (
	"bytes"
	"net"
	"testing"
	"time"

	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

// A server offering MS-CHAPv2 must now be accepted rather than Nak'd back to
// PAP: it is what Windows RRAS and MikroTik ask for by default, and it keeps
// the password off the wire.
func TestClientLCPAcceptsMSCHAPv2(t *testing.T) {
	clientFramer, serverFramer := lcpTestPipe(t)
	type result struct {
		method authMethod
		err    error
	}
	done := make(chan result, 1)
	go func() {
		m, err := negotiateClientLCP(clientFramer, func(string, ...any) {})
		done <- result{m, err}
	}()

	clientRequest := readTestPPP(t, serverFramer)
	clientLCP, err := protocol.ExpectControl(clientRequest, protocol.PPPLCP, protocol.ConfigureRequest)
	if err != nil {
		t.Fatal(err)
	}
	chapOptions := protocol.MSCHAPv2AuthenticationOption()
	writeTestPPP(t, serverFramer, protocol.ConfigureRequest, 9, chapOptions)

	// The client must ACK the offer directly — no Nak round-trip.
	ack := readTestPPP(t, serverFramer)
	ackControl, err := protocol.ExpectControl(ack, protocol.PPPLCP, protocol.ConfigureAck)
	if err != nil {
		t.Fatal(err)
	}
	if ackControl.ID != 9 || !bytes.Equal(ackControl.Payload, chapOptions) {
		t.Fatalf("LCP ACK = %+v", ackControl)
	}
	writeTestPPP(t, serverFramer, protocol.ConfigureAck, clientLCP.ID, clientLCP.Payload)

	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.method != authMSCHAPv2 {
		t.Errorf("method = %v, want MS-CHAPv2", got.method)
	}
}

// PAP must keep working: some ocserv-style and appliance servers offer it.
func TestClientLCPAcceptsPAP(t *testing.T) {
	clientFramer, serverFramer := lcpTestPipe(t)
	type result struct {
		method authMethod
		err    error
	}
	done := make(chan result, 1)
	go func() {
		m, err := negotiateClientLCP(clientFramer, func(string, ...any) {})
		done <- result{m, err}
	}()

	clientRequest := readTestPPP(t, serverFramer)
	clientLCP, err := protocol.ExpectControl(clientRequest, protocol.PPPLCP, protocol.ConfigureRequest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestPPP(t, serverFramer, protocol.ConfigureRequest, 10, protocol.PAPAuthenticationOption())
	ack := readTestPPP(t, serverFramer)
	if _, err := protocol.ExpectControl(ack, protocol.PPPLCP, protocol.ConfigureAck); err != nil {
		t.Fatal(err)
	}
	writeTestPPP(t, serverFramer, protocol.ConfigureAck, clientLCP.ID, clientLCP.Payload)

	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.method != authPAP {
		t.Errorf("method = %v, want PAP", got.method)
	}
}

// An authentication protocol we cannot run must be Nak'd toward MS-CHAPv2 —
// the stronger of the two we support — rather than silently downgraded.
func TestClientLCPNaksUnsupportedAuthWithMSCHAPv2(t *testing.T) {
	clientFramer, serverFramer := lcpTestPipe(t)
	done := make(chan error, 1)
	go func() {
		_, err := negotiateClientLCP(clientFramer, func(string, ...any) {})
		done <- err
	}()

	clientRequest := readTestPPP(t, serverFramer)
	clientLCP, err := protocol.ExpectControl(clientRequest, protocol.PPPLCP, protocol.ConfigureRequest)
	if err != nil {
		t.Fatal(err)
	}
	// EAP: not implemented.
	eapOptions := []byte{protocol.LCPOptionAuthentication, 4, 0xc2, 0x27}
	writeTestPPP(t, serverFramer, protocol.ConfigureRequest, 11, eapOptions)

	nak := readTestPPP(t, serverFramer)
	nakControl, err := protocol.ExpectControl(nak, protocol.PPPLCP, protocol.ConfigureNak)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nakControl.Payload, protocol.MSCHAPv2AuthenticationOption()) {
		t.Fatalf("LCP NAK = %x, want MS-CHAPv2 option", nakControl.Payload)
	}

	writeTestPPP(t, serverFramer, protocol.ConfigureRequest, 12, protocol.MSCHAPv2AuthenticationOption())
	if _, err := protocol.ExpectControl(readTestPPP(t, serverFramer), protocol.PPPLCP, protocol.ConfigureAck); err != nil {
		t.Fatal(err)
	}
	writeTestPPP(t, serverFramer, protocol.ConfigureAck, clientLCP.ID, clientLCP.Payload)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func lcpTestPipe(t *testing.T) (client, server *protocol.Framer) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	return protocol.NewFramer(clientConn, clientConn), protocol.NewFramer(serverConn, serverConn)
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
