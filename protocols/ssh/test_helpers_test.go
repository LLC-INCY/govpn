package ssh

import (
	"net"
	"testing"
	"time"
)

// testTCPPair uses a kernel-buffered stream. net.Pipe cannot be used for an
// SSH handshake because both peers write their version string before reading;
// its zero-buffered writes would deadlock each other.
func testTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct {
		connection net.Conn
		err        error
	}, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		accepted <- struct {
			connection net.Conn
			err        error
		}{connection: connection, err: acceptErr}
	}()
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), 5*time.Second)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var server net.Conn
	select {
	case result := <-accepted:
		if result.err != nil {
			_ = client.Close()
			_ = listener.Close()
			t.Fatal(result.err)
		}
		server = result.connection
	case <-time.After(5 * time.Second):
		_ = client.Close()
		_ = listener.Close()
		t.Fatal("timed out accepting test TCP connection")
	}
	_ = listener.Close()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}
