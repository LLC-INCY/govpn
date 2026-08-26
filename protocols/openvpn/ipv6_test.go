package openvpn

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestOpenVPNIPv6OnlyDataChannel(t *testing.T) {
	port := testUDP6Port(t)
	ca, caCertificate, caKey := makeCA(t)
	serverCert, serverKey := makeLeaf(t, caCertificate, caKey, true)
	clientCert, clientKey := makeLeaf(t, caCertificate, caKey, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := NewServer(ServerConfig{
		CA: ca, Cert: serverCert, Key: serverKey,
		ListenIP: "::1", ListenPort: port, Protocol: "udp6",
		Pool6: "fd77:6::/64", DataCiphers: []string{"AES-256-GCM"},
	}).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	listener, err := server.Listen("tcp6", "[fd77:6::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	const payload = "openvpn ipv6 works"
	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- acceptErr
			return
		}
		defer conn.Close()
		_, writeErr := conn.Write([]byte(payload))
		accepted <- writeErr
	}()

	client, err := NewClient(Config{
		Remote: "::1", Port: port, Protocol: "udp6",
		CA: ca, Cert: clientCert, Key: clientKey,
		DataCiphers: []string{"AES-256-GCM"},
	}).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if got := client.Addresses(); len(got) != 1 || !got[0].Addr().Is6() || got[0].String() != "fd77:6::2/64" {
		t.Fatalf("client addresses = %v", got)
	}

	conn, err := client.DialContext(ctx, "tcp6", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func testUDP6Port(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}
