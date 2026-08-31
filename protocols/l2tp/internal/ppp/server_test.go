package ppp

import (
	"net"
	"sync"
	"testing"

	"github.com/bclswl0827/govpn/internal/mschap"
)

type transportFunc func([]byte) error

func (f transportFunc) SendPPP(frame []byte) error { return f(frame) }

type testWire struct {
	mu                 sync.Mutex
	toClient, toServer [][]byte
}

func (w *testWire) clientTransport() Transport {
	return transportFunc(func(frame []byte) error {
		w.mu.Lock()
		w.toServer = append(w.toServer, append([]byte(nil), frame...))
		w.mu.Unlock()
		return nil
	})
}

func (w *testWire) serverTransport() Transport {
	return transportFunc(func(frame []byte) error {
		w.mu.Lock()
		w.toClient = append(w.toClient, append([]byte(nil), frame...))
		w.mu.Unlock()
		return nil
	})
}

func (w *testWire) drive(client *Session, server *ServerSession) {
	for range 200 {
		w.mu.Lock()
		toServer, toClient := w.toServer, w.toClient
		w.toServer, w.toClient = nil, nil
		w.mu.Unlock()
		if len(toServer) == 0 && len(toClient) == 0 {
			return
		}
		for _, frame := range toServer {
			server.Receive(frame)
		}
		for _, frame := range toClient {
			client.Receive(frame)
		}
	}
}

type clientRecordHandler struct {
	authed     bool
	ntResponse [mschap.NTResponseLen]byte
	up         bool
	config     IPConfig
	err        error
}

func (h *clientRecordHandler) Authenticated(response [mschap.NTResponseLen]byte) {
	h.authed = true
	h.ntResponse = response
}

func (h *clientRecordHandler) NetworkUp(config IPConfig) {
	h.up = true
	h.config = config
}

func (h *clientRecordHandler) Closed(err error) { h.err = err }

type serverRecordHandler struct {
	authed     bool
	username   string
	ntResponse [mschap.NTResponseLen]byte
	up         bool
	err        error
}

func (h *serverRecordHandler) Authenticated(username, _ string, response [mschap.NTResponseLen]byte) {
	h.authed = true
	h.username = username
	h.ntResponse = response
}

func (h *serverRecordHandler) NetworkUp()       { h.up = true }
func (h *serverRecordHandler) Closed(err error) { h.err = err }

func TestServerClientHandshake(t *testing.T) {
	const username, password = "alice", "s3cret"
	wire := &testWire{}
	clientHandler := &clientRecordHandler{}
	client := New(username, password, wire.clientTransport(), clientHandler)
	serverHandler := &serverRecordHandler{}
	server := NewServer(ServerConfig{
		ClientIP: net.IPv4(10, 20, 0, 2),
		ServerIP: net.IPv4(10, 20, 0, 1),
		DNS:      []net.IP{net.IPv4(8, 8, 8, 8)},
		Auth: func(candidate string) (string, bool) {
			return password, candidate == username
		},
	}, wire.serverTransport(), serverHandler)

	client.Start()
	server.Start()
	wire.drive(client, server)

	if !serverHandler.authed || serverHandler.username != username {
		t.Fatalf("server authentication = (%v, %q), want (true, %q)", serverHandler.authed, serverHandler.username, username)
	}
	if !clientHandler.authed {
		t.Fatal("client did not accept the server authenticator response")
	}
	if serverHandler.ntResponse != clientHandler.ntResponse {
		t.Fatal("client and server recorded different NT responses")
	}
	if !serverHandler.up || !clientHandler.up {
		t.Fatalf("network state = (server %v, client %v), want both up", serverHandler.up, clientHandler.up)
	}
	if !clientHandler.config.LocalIP.Equal(net.IPv4(10, 20, 0, 2)) {
		t.Errorf("assigned address = %v, want 10.20.0.2", clientHandler.config.LocalIP)
	}
	if !clientHandler.config.PeerIP.Equal(net.IPv4(10, 20, 0, 1)) {
		t.Errorf("peer address = %v, want 10.20.0.1", clientHandler.config.PeerIP)
	}
	if len(clientHandler.config.DNS) != 1 || !clientHandler.config.DNS[0].Equal(net.IPv4(8, 8, 8, 8)) {
		t.Errorf("DNS = %v, want [8.8.8.8]", clientHandler.config.DNS)
	}
	if clientHandler.err != nil || serverHandler.err != nil {
		t.Errorf("unexpected close: client=%v server=%v", clientHandler.err, serverHandler.err)
	}
}

func TestServerRejectsWrongPassword(t *testing.T) {
	wire := &testWire{}
	clientHandler := &clientRecordHandler{}
	client := New("alice", "wrong", wire.clientTransport(), clientHandler)
	serverHandler := &serverRecordHandler{}
	server := NewServer(ServerConfig{
		ClientIP: net.IPv4(10, 20, 0, 2),
		ServerIP: net.IPv4(10, 20, 0, 1),
		Auth:     func(string) (string, bool) { return "correct", true },
	}, wire.serverTransport(), serverHandler)

	client.Start()
	server.Start()
	wire.drive(client, server)

	if serverHandler.up || clientHandler.up {
		t.Fatal("network came up with an invalid password")
	}
	if serverHandler.err == nil || clientHandler.err == nil {
		t.Fatalf("authentication errors = (server %v, client %v), want both non-nil", serverHandler.err, clientHandler.err)
	}
}
