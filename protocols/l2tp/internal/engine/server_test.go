package engine

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bclswl0827/govpn/protocols/l2tp/internal/ppp"
)

type fakeTUN struct {
	in  chan []byte
	out chan []byte
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{in: make(chan []byte, 16), out: make(chan []byte, 16)}
}

func (f *fakeTUN) Read(buffer []byte) (int, error) {
	packet, ok := <-f.in
	if !ok {
		return 0, io.EOF
	}
	return copy(buffer, packet), nil
}

func (f *fakeTUN) Write(packet []byte) (int, error) {
	f.out <- append([]byte(nil), packet...)
	return len(packet), nil
}

func TestClientServerLoopback(t *testing.T) {
	loopback := net.IPv4(127, 0, 0, 1)
	ikeConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	nattConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback})
	if err != nil {
		_ = ikeConn.Close()
		t.Fatal(err)
	}
	_, network, err := net.ParseCIDR("10.20.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	gateway := net.IPv4(10, 20, 0, 1)
	serverTUN := newFakeTUN()
	server := NewServer(ikeConn, nattConn, serverTUN, ServerConfig{
		PSK:      []byte("shared-secret"),
		Users:    map[string]string{"alice": "password"},
		PublicIP: loopback,
		Network:  network,
		Gateway:  gateway,
		IKEPort:  ikeConn.LocalAddr().(*net.UDPAddr).Port,
		NATTPort: nattConn.LocalAddr().(*net.UDPAddr).Port,
	})
	go func() { _ = server.Serve() }()
	defer server.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	clientTUN := newFakeTUN()
	client := NewClient(clientConn, clientTUN, ClientConfig{
		ServerIP: loopback,
		LocalIP:  loopback,
		IKEPort:  ikeConn.LocalAddr().(*net.UDPAddr).Port,
		NATTPort: nattConn.LocalAddr().(*net.UDPAddr).Port,
		PSK:      []byte("shared-secret"),
		Username: "alice",
		Password: "password",
	})
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config, err := client.Handshake(ctx)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if !config.AssignedIP.Equal(net.IPv4(10, 20, 0, 2)) || !config.Gateway.Equal(gateway) {
		t.Fatalf("network config = %+v, want address 10.20.0.2 and gateway %s", config, gateway)
	}

	uplink := makeTestIPv4(config.AssignedIP, gateway)
	clientTUN.in <- uplink
	assertTestPacket(t, "client to server", serverTUN.out, uplink)

	downlink := makeTestIPv4(gateway, config.AssignedIP)
	serverTUN.in <- downlink
	assertTestPacket(t, "server to client", clientTUN.out, downlink)
}

func TestAddressPoolExhaustionAndRelease(t *testing.T) {
	_, network, err := net.ParseCIDR("10.20.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	pool := newAddressPool(network, net.IPv4(10, 20, 0, 1))
	address, err := pool.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if !address.Equal(net.IPv4(10, 20, 0, 2)) {
		t.Fatalf("allocated address = %v, want 10.20.0.2", address)
	}
	if _, err := pool.Allocate(); err != errAddressPoolExhausted {
		t.Fatalf("second allocation error = %v, want %v", err, errAddressPoolExhausted)
	}
	pool.Release(address)
	reused, err := pool.Allocate()
	if err != nil || !reused.Equal(address) {
		t.Fatalf("allocation after release = %v, %v; want %v, nil", reused, err, address)
	}
}

func TestServerPeerRejectsIPBeforeNetworkUpAndSpoofedSource(t *testing.T) {
	tun := newFakeTUN()
	peer := &serverPeer{
		srv:     &Server{tun: tun},
		innerIP: net.IPv4(10, 20, 0, 2),
	}
	valid := makeTestIPv4(net.IPv4(10, 20, 0, 2), net.IPv4(10, 20, 0, 1))
	peer.DataFrame(ppp.EncapsulateIP(valid))
	assertNoTestPacket(t, tun.out)

	peer.networkUp = true
	spoofed := makeTestIPv4(net.IPv4(10, 20, 0, 3), net.IPv4(10, 20, 0, 1))
	peer.DataFrame(ppp.EncapsulateIP(spoofed))
	assertNoTestPacket(t, tun.out)

	peer.DataFrame(ppp.EncapsulateIP(valid))
	assertTestPacket(t, "authenticated client to server", tun.out, valid)
}

func makeTestIPv4(source, destination net.IP) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2], packet[3] = 0, 20
	packet[9] = 1
	copy(packet[12:16], source.To4())
	copy(packet[16:20], destination.To4())
	return packet
}

func assertTestPacket(t *testing.T, direction string, packets <-chan []byte, want []byte) {
	t.Helper()
	select {
	case got := <-packets:
		if !bytes.Equal(got, want) {
			t.Errorf("%s packet = %x, want %x", direction, got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s packet", direction)
	}
}

func assertNoTestPacket(t *testing.T, packets <-chan []byte) {
	t.Helper()
	select {
	case packet := <-packets:
		t.Fatalf("unexpected packet %x", packet)
	default:
	}
}
