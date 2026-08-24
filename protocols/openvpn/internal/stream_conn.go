package openvpn

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// StreamConn adapts OpenVPN's length-prefixed TCP transport to the datagram
// boundary consumed by endpoint.
type StreamConn struct {
	net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func NewStreamConn(conn net.Conn) *StreamConn {
	return &StreamConn{Conn: conn}
}

func (c *StreamConn) Read(buffer []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var header [2]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length == 0 {
		return 0, errors.New("openvpn: empty TCP frame")
	}
	if length > len(buffer) {
		_, _ = io.CopyN(io.Discard, c.Conn, int64(length))
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(c.Conn, buffer[:length])
}

func (c *StreamConn) Write(packet []byte) (int, error) {
	if len(packet) == 0 || len(packet) > 65535 {
		return 0, errors.New("openvpn: invalid TCP frame size")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	framed := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(packet)))
	copy(framed[2:], packet)
	for written := 0; written < len(framed); {
		n, err := c.Conn.Write(framed[written:])
		written += n
		if err != nil {
			if written <= 2 {
				return 0, err
			}
			return written - 2, err
		}
		if n == 0 {
			return 0, io.ErrUnexpectedEOF
		}
	}
	return len(packet), nil
}

var _ net.Conn = (*StreamConn)(nil)
