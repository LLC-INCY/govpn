package softether

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
	protocol "github.com/bclswl0827/govpn/protocols/softether/internal"
)

type Client struct{ Config Config }

func NewClient(config Config) *Client { return &Client{Config: config} }

func (c *Client) Start(ctx context.Context) (*govpn.Session, error) {
	if c.Config.Server == "" || c.Config.Hub == "" || c.Config.Username == "" {
		return nil, errors.New("softether: server, hub, and username are required")
	}
	port := c.Config.Port
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("softether: port is out of range")
	}
	if c.Config.MaxConnections < 0 || c.Config.MaxConnections > 32 {
		return nil, errors.New("softether: MaxConnections is out of range")
	}
	if c.Config.ConnectTimeout < 0 {
		return nil, errors.New("softether: ConnectTimeout cannot be negative")
	}
	if c.Config.OpenSSLCompat && c.Config.DisableEncryption {
		return nil, errors.New("softether: OpenSSLCompat requires tunnel encryption")
	}
	if c.Config.MaxConnections > 1 || c.Config.HalfConnection || c.Config.EnableQoS {
		return nil, errors.New("softether: additional TCP connections, half-connection, and QoS are not implemented yet")
	}
	tlsConfig, err := clientTLSConfig(c.Config)
	if err != nil {
		return nil, err
	}
	connectTimeout := c.Config.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = 15 * time.Second
	}
	connectCtx, cancelConnect := context.WithTimeout(ctx, connectTimeout)
	defer cancelConnect()
	remoteAddress := net.JoinHostPort(c.Config.Server, strconv.Itoa(port))
	c.logf("connecting: remote=%s", remoteAddress)
	rawConn, err := (&net.Dialer{}).DialContext(connectCtx, "tcp", remoteAddress)
	if err != nil {
		return nil, fmt.Errorf("softether: dial: %w", err)
	}
	if deadline, ok := connectCtx.Deadline(); ok {
		if err := rawConn.SetDeadline(deadline); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("softether: set handshake deadline: %w", err)
		}
	}
	c.logf("TCP connected: local=%s remote=%s", rawConn.LocalAddr(), rawConn.RemoteAddr())
	wireConn := &tunnelWireTrace{Conn: rawConn, logf: c.logf}
	conn := tls.Client(wireConn, tlsConfig)
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = rawConn.Close()
		}
	}()
	if err := conn.HandshakeContext(connectCtx); err != nil {
		return nil, fmt.Errorf("softether: TLS handshake: %w", err)
	}
	c.logf("TLS handshake completed: version=0x%04x cipher-suite=0x%04x", conn.ConnectionState().Version, conn.ConnectionState().CipherSuite)
	reader := bufio.NewReader(conn)
	host := net.JoinHostPort(c.Config.Server, strconv.Itoa(port))
	parameters, err := clientHandshake(c.Config, conn, reader, host)
	if err != nil {
		return nil, err
	}
	if err := rawConn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("softether: clear handshake deadline: %w", err)
	}
	c.logf("native session established: encryption=%t compression=%t", parameters.UseEncrypt, parameters.UseCompress)
	if c.Config.OpenSSLCompat {
		preamble := []byte{0, 1, 2, 3, 4}
		n, err := rawConn.Write(preamble)
		if err != nil {
			return nil, fmt.Errorf("softether: send OpenSSL compatibility preamble: %w", err)
		}
		if n != len(preamble) {
			return nil, fmt.Errorf("softether: send OpenSSL compatibility preamble: %w", io.ErrShortWrite)
		}
		c.logf("OpenSSL compatibility preamble sent")
	}
	wireConn.arm(parameters.UseEncrypt)
	streamReader, streamWriter := io.Reader(reader), io.Writer(conn)
	if !parameters.UseEncrypt {
		streamReader, streamWriter = wireConn, wireConn
	}
	stream := protocol.NewFrameStream(streamReader, streamWriter, parameters.UseCompress)
	localMAC, err := clientMAC()
	if err != nil {
		return nil, err
	}
	address, gateway, gatewayMAC, err := c.acquireAddress(ctx, conn, stream, localMAC)
	if err != nil {
		return nil, err
	}
	c.logf("network parameters acquired: address=%s gateway=%s", address, gateway)
	device, err := packet.New("softether-client", defaultMTU)
	if err != nil {
		return nil, err
	}
	transport := newTransport(rawConn, device, stream, localMAC, address, gateway, gatewayMAC, nil)
	done := make(chan error, 1)
	go transport.run(done)
	closeOnError = false
	return govpn.NewSession([]netip.Prefix{address}, defaultMTU, device, transport.Close, done)
}

func (c *Client) logf(format string, arguments ...any) {
	if c.Config.Logger != nil {
		c.Config.Logger.Printf("[softether] "+format, arguments...)
	}
}

type tunnelWireTrace struct {
	net.Conn
	mu         sync.Mutex
	readArmed  bool
	writeArmed bool
	encrypted  bool
	logf       func(string, ...any)
}

func (c *tunnelWireTrace) arm(encrypted bool) {
	c.mu.Lock()
	c.readArmed = true
	c.writeArmed = true
	c.encrypted = encrypted
	c.mu.Unlock()
}

func (c *tunnelWireTrace) Write(data []byte) (int, error) {
	c.mu.Lock()
	armed, encrypted := c.writeArmed, c.encrypted
	if armed {
		c.writeArmed = false
	}
	c.mu.Unlock()
	if armed {
		prefixLength := min(len(data), 16)
		c.logf("first tunnel wire write: encryption=%t bytes=%d prefix=%x", encrypted, len(data), data[:prefixLength])
	}
	return c.Conn.Write(data)
}

func (c *tunnelWireTrace) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	c.mu.Lock()
	armed, encrypted := c.readArmed, c.encrypted
	if armed && n != 0 {
		c.readArmed = false
	}
	c.mu.Unlock()
	if armed && n != 0 {
		prefixLength := min(n, 16)
		c.logf("first tunnel wire read: encryption=%t bytes=%d prefix=%x", encrypted, n, data[:prefixLength])
	}
	return n, err
}

func (c *Client) acquireAddress(ctx context.Context, conn net.Conn, stream *protocol.FrameStream, mac [6]byte) (netip.Prefix, netip.Addr, [6]byte, error) {
	if c.Config.Address != "" {
		address, err := netip.ParsePrefix(c.Config.Address)
		if err != nil || !address.Addr().Is4() {
			return netip.Prefix{}, netip.Addr{}, [6]byte{}, fmt.Errorf("softether: invalid static IPv4 address %q", c.Config.Address)
		}
		gateway := netip.Addr{}
		if c.Config.Gateway != "" {
			gateway, err = netip.ParseAddr(c.Config.Gateway)
			if err != nil || !gateway.Is4() {
				return netip.Prefix{}, netip.Addr{}, [6]byte{}, fmt.Errorf("softether: invalid IPv4 gateway %q", c.Config.Gateway)
			}
		} else {
			gateway = address.Masked().Addr().Next()
		}
		deadline := c.addressDeadline(ctx)
		if err := conn.SetDeadline(deadline); err != nil {
			return netip.Prefix{}, netip.Addr{}, [6]byte{}, err
		}
		gatewayMAC, err := protocol.ResolveARP(stream, mac, address.Addr(), gateway)
		_ = conn.SetDeadline(time.Time{})
		if err != nil {
			return netip.Prefix{}, netip.Addr{}, [6]byte{}, fmt.Errorf("softether: resolve gateway %s: %w", gateway, err)
		}
		return address, gateway, gatewayMAC, nil
	}
	deadline := c.addressDeadline(ctx)
	if err := conn.SetDeadline(deadline); err != nil {
		return netip.Prefix{}, netip.Addr{}, [6]byte{}, err
	}
	lease, err := protocol.AcquireDHCP(stream, mac)
	if err != nil {
		_ = conn.SetDeadline(time.Time{})
		return netip.Prefix{}, netip.Addr{}, [6]byte{}, err
	}
	gatewayMAC := lease.ServerMAC
	if lease.Gateway.Is4() {
		gatewayMAC, err = protocol.ResolveARP(stream, mac, lease.Address.Addr(), lease.Gateway)
	}
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, [6]byte{}, fmt.Errorf("softether: resolve DHCP gateway %s: %w", lease.Gateway, err)
	}
	return lease.Address, lease.Gateway, gatewayMAC, nil
}

func (c *Client) addressDeadline(ctx context.Context) time.Time {
	timeout := c.Config.DHCPTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func clientMAC() ([6]byte, error) {
	var mac [6]byte
	if _, err := rand.Read(mac[:]); err != nil {
		return mac, fmt.Errorf("softether: generate client MAC: %w", err)
	}
	mac[0] = mac[0]&0xfe | 0x02
	return mac, nil
}
