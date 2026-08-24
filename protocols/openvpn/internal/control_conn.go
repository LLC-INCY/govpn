package openvpn

import (
	"bytes"
	"io"
	"net"
	"sync"
	"time"
)

type ControlConn struct {
	endpoint *endpoint
	readMu   sync.Mutex
	readBuf  bytes.Buffer
}

func NewControlConn(endpoint *endpoint) *ControlConn { return &ControlConn{endpoint: endpoint} }

func (c *ControlConn) Read(buffer []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for c.readBuf.Len() == 0 {
		select {
		case payload := <-c.endpoint.controlCh:
			_, _ = c.readBuf.Write(payload)
		case err := <-c.endpoint.errCh:
			return 0, err
		case <-c.endpoint.closed:
			return 0, io.ErrClosedPipe
		}
	}
	return c.readBuf.Read(buffer)
}

func (c *ControlConn) Write(buffer []byte) (int, error) {
	written := 0
	for len(buffer) != 0 {
		size := len(buffer)
		if size > MaxControlPayload {
			size = MaxControlPayload
		}
		if err := c.endpoint.sendControl(buffer[:size]); err != nil {
			return written, err
		}
		written += size
		buffer = buffer[size:]
	}
	return written, nil
}

func (c *ControlConn) Close() error                       { return c.endpoint.Close() }
func (c *ControlConn) LocalAddr() net.Addr                { return c.endpoint.conn.LocalAddr() }
func (c *ControlConn) RemoteAddr() net.Addr               { return c.endpoint.conn.RemoteAddr() }
func (c *ControlConn) SetDeadline(t time.Time) error      { return c.endpoint.conn.SetDeadline(t) }
func (c *ControlConn) SetReadDeadline(t time.Time) error  { return c.endpoint.conn.SetReadDeadline(t) }
func (c *ControlConn) SetWriteDeadline(t time.Time) error { return c.endpoint.conn.SetWriteDeadline(t) }
