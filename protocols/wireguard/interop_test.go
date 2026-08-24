package wireguard

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	officialnet "golang.zx2c4.com/wireguard/tun/netstack"
)

func TestOfficialUserspaceInterop(t *testing.T) {
	t.Run("official client to library server", testOfficialClientToLibraryServer)
	t.Run("library client to official server", testLibraryClientToOfficialServer)
}

func testOfficialClientToLibraryServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	port := testUDPPort(t)
	serverPrivate, serverPublic, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientPrivate, clientPublic, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}

	server := NewServer(ServerConfig{
		PrivateKey: serverPrivate, ListenPort: port,
		Address: "10.91.0.1/24", Address6: "fd91::1/64",
		Peers: []ServerPeer{{
			PublicKey: clientPublic, PresharedKey: psk,
			AllowedIPs: []string{"10.91.0.2/32", "fd91::2/128"},
		}},
	})
	serverSession, err := server.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	officialNetwork := startOfficialPeer(t,
		[]netip.Addr{netip.MustParseAddr("10.91.0.2"), netip.MustParseAddr("fd91::2")},
		clientPrivate, 0, Peer{
			PublicKey: serverPublic, PresharedKey: psk,
			Endpoint:   fmt.Sprintf("127.0.0.1:%d", port),
			AllowedIPs: []string{"10.91.0.0/24", "fd91::/64"}, Keepalive: 1,
		})

	listener, err := serverSession.Listen("tcp4", "10.91.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverErr := echoOnce(listener)

	connection, err := officialNetwork.DialContext(ctx, "tcp4", "10.91.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	exchangePing(t, connection)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	listener6, err := serverSession.Listen("tcp6", "[fd91::1]:18081")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener6.Close() })
	serverErr6 := echoOnce(listener6)
	connection6, err := officialNetwork.DialContext(ctx, "tcp6", "[fd91::1]:18081")
	if err != nil {
		t.Fatal(err)
	}
	exchangePing(t, connection6)
	if err := <-serverErr6; err != nil {
		t.Fatal(err)
	}
	status, err := server.Status()
	if err != nil {
		t.Fatal(err)
	}
	assertHandshakeStatus(t, status)
}

func testLibraryClientToOfficialServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	port := testUDPPort(t)
	serverPrivate, serverPublic, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientPrivate, clientPublic, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}

	officialNetwork := startOfficialPeer(t,
		[]netip.Addr{netip.MustParseAddr("10.92.0.1"), netip.MustParseAddr("fd92::1")},
		serverPrivate, port, Peer{
			PublicKey: clientPublic, PresharedKey: psk,
			AllowedIPs: []string{"10.92.0.2/32", "fd92::2/128"},
		})

	client := NewClient(Config{
		PrivateKey: clientPrivate, Address: []string{"10.92.0.2/24", "fd92::2/64"},
		Peers: []Peer{{
			PublicKey: serverPublic, PresharedKey: psk,
			Endpoint:   fmt.Sprintf("127.0.0.1:%d", port),
			AllowedIPs: []string{"10.92.0.0/24", "fd92::/64"}, Keepalive: 1,
		}},
	})
	clientSession, err := client.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })

	listener, err := officialNetwork.ListenTCPAddrPort(netip.MustParseAddrPort("10.92.0.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverErr := echoOnce(listener)

	connection, err := clientSession.DialContext(ctx, "tcp4", "10.92.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	exchangePing(t, connection)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	listener6, err := officialNetwork.ListenTCPAddrPort(netip.MustParseAddrPort("[fd92::1]:18081"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener6.Close() })
	serverErr6 := echoOnce(listener6)
	connection6, err := clientSession.DialContext(ctx, "tcp6", "[fd92::1]:18081")
	if err != nil {
		t.Fatal(err)
	}
	exchangePing(t, connection6)
	if err := <-serverErr6; err != nil {
		t.Fatal(err)
	}
	status, err := client.Status()
	if err != nil {
		t.Fatal(err)
	}
	assertHandshakeStatus(t, status)
	emptyPSK := ""
	disabledKeepalive := 0
	runtime, err := client.Runtime()
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.UpdatePeer(ctx, PeerUpdate{
		PublicKey: serverPublic, UpdateOnly: true,
		PresharedKey: &emptyPSK, Keepalive: &disabledKeepalive,
	}); err != nil {
		t.Fatal(err)
	}
	status, err = client.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Peers) != 1 || status.Peers[0].Keepalive != 0 {
		t.Fatalf("WireGuard status after runtime update = %+v", status)
	}
}

func startOfficialPeer(t *testing.T, addresses []netip.Addr, privateKey string, listenPort int, peer Peer) *officialnet.Net {
	t.Helper()
	tunnel, network, err := officialnet.CreateNetTUN(addresses, nil, defaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	official := device.NewDevice(tunnel, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(official.Close)
	privateHex, err := keyHex(privateKey, false)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := preparePeers(context.Background(), []Peer{peer})
	if err != nil {
		t.Fatal(err)
	}
	var configuration strings.Builder
	fmt.Fprintf(&configuration, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", privateHex, listenPort)
	if err := appendPeerConfiguration(&configuration, prepared); err != nil {
		t.Fatal(err)
	}
	if err := official.IpcSet(configuration.String()); err != nil {
		t.Fatal(err)
	}
	if err := official.Up(); err != nil {
		t.Fatal(err)
	}
	return network
}

func echoOnce(listener net.Listener) <-chan error {
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		request := make([]byte, 4)
		if _, err := io.ReadFull(connection, request); err != nil {
			done <- err
			return
		}
		if string(request) != "ping" {
			done <- fmt.Errorf("unexpected request %q", request)
			return
		}
		_, err = connection.Write([]byte("pong"))
		done <- err
	}()
	return done
}

func exchangePing(t *testing.T, connection net.Conn) {
	t.Helper()
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("unexpected response %q", response)
	}
}

func assertHandshakeStatus(t *testing.T, status Status) {
	t.Helper()
	if len(status.Peers) != 1 || status.Peers[0].LastHandshake.IsZero() ||
		status.Peers[0].TransmitBytes == 0 || status.Peers[0].ReceiveBytes == 0 {
		t.Fatalf("WireGuard status after exchange = %+v", status)
	}
}

func testUDPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
