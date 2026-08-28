package sstp

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/bclswl0827/govpn/internal/packet"
	transportutil "github.com/bclswl0827/govpn/internal/transport"
	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

type serverTransport struct {
	listener net.Listener
	device   *packet.Device
	mu       sync.Mutex
	conn     net.Conn
	once     sync.Once
}

func newServerTransport(listener net.Listener, device *packet.Device) *serverTransport {
	return &serverTransport{listener: listener, device: device}
}

func (t *serverTransport) Close() error {
	var err error
	t.once.Do(func() {
		t.mu.Lock()
		conn := t.conn
		t.mu.Unlock()
		if conn != nil {
			err = conn.Close()
		}
		err = errors.Join(err, t.listener.Close(), t.device.Close())
	})
	return err
}

func (t *serverTransport) accept(users map[string]string, assigned netip.Addr, certificateDER []byte, done chan<- error) {
	conn, err := t.listener.Accept()
	if err != nil {
		done <- transportutil.NormalizeError(err)
		return
	}
	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()
	reader := bufio.NewReader(conn)
	err = protocol.ReadClientHTTP(reader)
	if err == nil {
		err = protocol.WriteServerHTTP(conn)
	}
	framer := protocol.NewFramer(reader, conn)
	if err == nil {
		err = serverHandshake(framer, users, assigned, certificateDER)
	}
	if err != nil {
		_ = t.Close()
		done <- err
		return
	}
	newTransport(conn, t.device, nil).run(framer, done)
}
