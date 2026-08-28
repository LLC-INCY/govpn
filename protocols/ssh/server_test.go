package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bclswl0827/govpn"
	gossh "golang.org/x/crypto/ssh"
)

func TestPureGoServerClientRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hostKey := testHostPrivateKey(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := NewServer(ServerConfig{
		HostKey: hostKey,
		Users: map[string]ServerUser{
			"alice": {Password: "secret"},
		},
		ResolveTunnel: func(_ context.Context, connection *gossh.ServerConn, request TunnelRequest) (TunnelSettings, error) {
			if connection.User() != "alice" || request.Mode != TunnelModePointToPoint || request.Unit != 7 {
				return TunnelSettings{}, fmt.Errorf("unexpected tunnel request: user=%q request=%+v", connection.User(), request)
			}
			return TunnelSettings{Address: []string{"10.90.0.1/30", "fd90::1/126"}, MTU: 1400}, nil
		},
	})
	serverResult := make(chan sessionResult, 1)
	go func() {
		rawConnection, acceptErr := listener.Accept()
		_ = listener.Close()
		if acceptErr != nil {
			serverResult <- sessionResult{err: acceptErr}
			return
		}
		handleErr := server.HandleConn(ctx, rawConnection, func(_ context.Context, _ *gossh.ServerConn, session *govpn.Session) {
			serverResult <- sessionResult{session: session}
		})
		if handleErr != nil {
			select {
			case serverResult <- sessionResult{err: handleErr}:
			default:
			}
		}
	}()

	unit := 7
	clientSession, err := NewClient(Config{
		Server:              listener.Addr().String(),
		User:                "alice",
		Password:            "secret",
		InsecureSkipHostKey: true,
		Address:             []string{"10.90.0.2/30", "fd90::2/126"},
		MTU:                 1400,
		RemoteTunnel:        &unit,
	}).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })

	var serverSession *govpn.Session
	select {
	case result := <-serverResult:
		if result.err != nil {
			t.Fatal(result.err)
		}
		serverSession = result.session
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	exerciseSSHTunnelTCP(ctx, t, serverSession, clientSession, "tcp4", "10.90.0.1:8080")
	exerciseSSHTunnelTCP(ctx, t, serverSession, clientSession, "tcp6", "[fd90::1]:8081")
}

func exerciseSSHTunnelTCP(ctx context.Context, t *testing.T, serverSession, clientSession *govpn.Session, network, address string) {
	t.Helper()
	service, err := serverSession.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	echoResult := make(chan error, 1)
	go func() {
		connection, acceptErr := service.Accept()
		if acceptErr != nil {
			echoResult <- acceptErr
			return
		}
		defer connection.Close()
		_, copyErr := io.Copy(connection, connection)
		echoResult <- copyErr
	}()

	connection, err := clientSession.DialContext(ctx, network, address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "ping" {
		t.Fatalf("reply = %q, want ping", reply)
	}
	_ = connection.Close()
	if err := <-echoResult; err != nil {
		t.Fatal(err)
	}
}

func TestServerHandlerRegistration(t *testing.T) {
	server := NewServer(ServerConfig{})
	channelHandler := func(context.Context, *gossh.ServerConn, gossh.NewChannel) {}
	globalHandler := func(context.Context, *gossh.ServerConn, *gossh.Request) {}
	sessionHandler := func(context.Context, *ServerSession, *gossh.Request) {}

	if err := server.RegisterChannelHandler("direct-tcpip", channelHandler); err != nil {
		t.Fatal(err)
	}
	if err := server.RegisterGlobalRequestHandler("tcpip-forward", globalHandler); err != nil {
		t.Fatal(err)
	}
	if err := server.RegisterSessionRequestHandler("pty-req", sessionHandler); err != nil {
		t.Fatal(err)
	}
	if err := server.RegisterSessionRequestHandler("subsystem", sessionHandler); err != nil {
		t.Fatal(err)
	}
	if err := server.RegisterChannelHandler("direct-tcpip", channelHandler); err == nil {
		t.Fatal("duplicate channel handler registration succeeded")
	}
	if err := server.RegisterChannelHandler("tun@openssh.com", channelHandler); err == nil {
		t.Fatal("reserved TUN handler registration succeeded")
	}
}

func TestHandleConnServesSessionWithoutTunnel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server := NewServer(ServerConfig{
		HostKey: testHostPrivateKey(t),
		Users: map[string]ServerUser{
			"alice": {Password: "secret"},
		},
		Address: []string{"10.90.0.1/30"},
	})
	if err := server.RegisterSessionRequestHandler("exec", func(_ context.Context, session *ServerSession, request *gossh.Request) {
		if request.WantReply {
			_ = request.Reply(true, nil)
		}
		_, _ = session.Channel.Write([]byte("session without tunnel"))
		_ = session.Channel.Close()
	}); err != nil {
		t.Fatal(err)
	}

	clientConnection, serverConnection := testTCPPair(t)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.HandleConn(ctx, serverConnection, nil) }()
	connection, channels, requests, err := gossh.NewClientConn(clientConnection, "pipe", &gossh.ClientConfig{
		User:            "alice",
		Auth:            []gossh.AuthMethod{gossh.Password("secret")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := gossh.NewClient(connection, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start("ignored"); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	_ = session.Wait()
	if string(output) != "session without tunnel" {
		t.Fatalf("output = %q", output)
	}
	_ = client.Close()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestParseTunnelRequest(t *testing.T) {
	payload := gossh.Marshal(TunnelRequest{Mode: TunnelModePointToPoint, Unit: TunnelUnitAny})
	request, err := parseTunnelRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if request.Mode != TunnelModePointToPoint || request.Unit != TunnelUnitAny {
		t.Fatalf("request = %+v", request)
	}
	if _, err := parseTunnelRequest(gossh.Marshal(TunnelRequest{Mode: 2, Unit: 0})); err == nil {
		t.Fatal("unsupported tunnel mode was accepted")
	}
	if _, err := parseTunnelRequest([]byte{1, 2, 3}); err == nil {
		t.Fatal("malformed tunnel request was accepted")
	}
}

type sessionResult struct {
	session *govpn.Session
	err     error
}

func testHostPrivateKey(t *testing.T) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}
