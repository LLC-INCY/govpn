package sstp

import (
	"net"
	"net/netip"
	"testing"
	"time"

	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

func TestClientIPCPStartsNegotiationAndAcceptsAddress(t *testing.T) {
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
	done := make(chan struct {
		address netip.Addr
		err     error
	}, 1)
	go func() {
		address, err := negotiateClientIPCP(clientFramer, func(string, ...any) {})
		done <- struct {
			address netip.Addr
			err     error
		}{address: address, err: err}
	}()

	initial := readTestPPP(t, serverFramer)
	initialControl, err := protocol.ExpectControl(initial, protocol.PPPIPCP, protocol.ConfigureRequest)
	if err != nil {
		t.Fatal(err)
	}
	if address, ok := protocol.ParseIPv4Option(initialControl.Payload); !ok || !address.IsUnspecified() {
		t.Fatalf("initial IPCP address = %s, %t", address, ok)
	}

	gateway := netip.MustParseAddr("10.20.0.1")
	assigned := netip.MustParseAddr("10.20.0.2")
	writeTestIPCP(t, serverFramer, protocol.ConfigureRequest, 8, protocol.IPv4Option(gateway))
	if _, err := protocol.ExpectControl(readTestPPP(t, serverFramer), protocol.PPPIPCP, protocol.ConfigureAck); err != nil {
		t.Fatal(err)
	}
	writeTestIPCP(t, serverFramer, protocol.ConfigureNak, initialControl.ID, protocol.IPv4Option(assigned))
	assignedRequest := readTestPPP(t, serverFramer)
	assignedControl, err := protocol.ExpectControl(assignedRequest, protocol.PPPIPCP, protocol.ConfigureRequest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestIPCP(t, serverFramer, protocol.ConfigureAck, assignedControl.ID, assignedControl.Payload)

	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.address != assigned {
		t.Fatalf("assigned address = %s", result.address)
	}
}

func writeTestIPCP(t *testing.T, framer *protocol.Framer, code, id byte, options []byte) {
	t.Helper()
	if err := framer.WriteData(protocol.EncodePPP(protocol.PPPIPCP, protocol.EncodeControl(code, id, options))); err != nil {
		t.Fatal(err)
	}
}
