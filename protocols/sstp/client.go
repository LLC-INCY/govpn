package sstp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

type Client struct{ Config Config }

func NewClient(config Config) *Client { return &Client{Config: config} }

// connect dials the server, opens the SSTP tunnel and runs the SSTP+PPP
// handshake. Shared by Start and StartTunnel, which differ only in what they
// hand back afterwards.
//
// On success the caller owns conn and must close it if it fails to build a
// session around it.
func (c *Client) connect(ctx context.Context) (net.Conn, *protocol.Framer, netip.Addr, error) {
	if c.Config.Server == "" {
		return nil, nil, netip.Addr{}, errors.New("sstp: server is required")
	}
	if c.Config.Port <= 0 || c.Config.Port > 65535 {
		return nil, nil, netip.Addr{}, fmt.Errorf("sstp: port %d is out of range", c.Config.Port)
	}
	roots, err := certificatePool(c.Config.CA)
	if err != nil {
		return nil, nil, netip.Addr{}, err
	}
	serverName := c.Config.ServerName
	if serverName == "" {
		serverName = c.Config.Server
	}
	remoteAddress := net.JoinHostPort(c.Config.Server, strconv.Itoa(c.Config.Port))
	c.logf("starting client: remote=%s server-name=%s skip-verify=%t", remoteAddress, serverName, c.Config.SkipVerify)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName, InsecureSkipVerify: c.Config.SkipVerify}
	dialer := tls.Dialer{Config: tlsConfig, NetDialer: c.Config.Dialer}
	c.logf("connecting TLS transport")
	conn, err := dialer.DialContext(ctx, "tcp", remoteAddress)
	if err != nil {
		return nil, nil, netip.Addr{}, fmt.Errorf("sstp: TLS dial: %w", err)
	}
	tlsState := conn.(*tls.Conn).ConnectionState()
	c.logf("TLS transport connected: local=%s remote=%s version=0x%04x cipher-suite=0x%04x", conn.LocalAddr(), conn.RemoteAddr(), tlsState.Version, tlsState.CipherSuite)
	setClientHandshakeDeadline(ctx, conn)
	handshakeDone := make(chan struct{})
	defer close(handshakeDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-handshakeDone:
		}
	}()
	c.logf("opening SSTP HTTP tunnel")
	if err := protocol.WriteClientHTTP(conn, remoteAddress); err != nil {
		return nil, nil, netip.Addr{}, clientContextError(ctx, err)
	}
	reader := bufio.NewReader(conn)
	if err := protocol.ReadServerHTTP(reader); err != nil {
		return nil, nil, netip.Addr{}, clientContextError(ctx, err)
	}
	c.logf("SSTP HTTP tunnel established")
	framer := protocol.NewFramer(reader, conn)
	if len(tlsState.PeerCertificates) == 0 {
		return nil, nil, netip.Addr{}, errors.New("sstp: server sent no certificate")
	}
	c.logf("starting SSTP and PPP negotiation")
	assigned, err := clientHandshake(framer, c.Config.Username, c.Config.Password, tlsState.PeerCertificates[0].Raw, c.logf)
	if err != nil {
		return nil, nil, netip.Addr{}, clientContextError(ctx, err)
	}
	_ = conn.SetDeadline(time.Time{})
	if err := ctx.Err(); err != nil {
		return nil, nil, netip.Addr{}, err
	}
	return conn, framer, assigned, nil
}

func (c *Client) Start(ctx context.Context) (*govpn.Session, error) {
	conn, framer, assigned, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()
	prefixLength := c.Config.PrefixLength
	if prefixLength == 0 {
		prefixLength = 24
	}
	if prefixLength < 1 || prefixLength > 32 {
		return nil, errors.New("sstp: prefix length is out of range")
	}
	device, err := packet.New("sstp-client", defaultMTU)
	if err != nil {
		return nil, err
	}
	transport := newTransport(conn, device, c.Config.Logger)
	done := make(chan error, 1)
	go transport.run(framer, done)
	session, err := govpn.NewSession([]netip.Prefix{netip.PrefixFrom(assigned, prefixLength)}, defaultMTU, device, transport.Close, done)
	if err != nil {
		return nil, err
	}
	closeOnError = false
	c.logf("data channel ready: address=%s/%d", assigned, prefixLength)
	return session, nil
}

// Tunnel is a connected SSTP session exposed as raw IP packets rather than a
// gVisor network stack.
//
// Start terminates traffic in-process, which suits a library that dials on the
// caller's behalf. An embedder that already owns an OS TUN device wants the
// opposite: the IP packets themselves, to pump between the tunnel and that
// device. StartTunnel returns exactly that.
type Tunnel struct {
	// Address is the IPv4 address the server assigned, with the configured
	// prefix length. The caller applies it to its own TUN device.
	Address netip.Prefix
	// MTU is the tunnel MTU.
	MTU int

	device    *packet.Device
	closeOnce sync.Once
	closeFn   func() error
	done      <-chan error
}

// ReadPacket returns the next IP packet received from the server. It blocks
// until a packet arrives, the context is cancelled, or the tunnel closes.
func (t *Tunnel) ReadPacket(ctx context.Context) ([]byte, error) {
	return t.device.Receive(ctx)
}

// WritePacket sends one IP packet to the server.
func (t *Tunnel) WritePacket(ctx context.Context, p []byte) error {
	return t.device.Inject(ctx, p)
}

// Done is closed with the transport's terminal error when the tunnel stops on
// its own, so the caller can surface why a live tunnel dropped.
func (t *Tunnel) Done() <-chan error { return t.done }

// Close tears the tunnel down. Safe to call more than once.
func (t *Tunnel) Close() error {
	var err error
	t.closeOnce.Do(func() {
		err = t.closeFn()
		_ = t.device.Close()
	})
	return err
}

// StartTunnel connects and authenticates like Start, but hands back raw IP
// packets instead of a gVisor stack. Routing, DNS and the TUN device stay the
// caller's responsibility — which is what a mobile VPN client needs, since the
// platform owns all three.
func (c *Client) StartTunnel(ctx context.Context) (*Tunnel, error) {
	conn, framer, assigned, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()

	prefixLength := c.Config.PrefixLength
	if prefixLength == 0 {
		prefixLength = 24
	}
	if prefixLength < 1 || prefixLength > 32 {
		return nil, errors.New("sstp: prefix length is out of range")
	}
	device, err := packet.New("sstp-client", defaultMTU)
	if err != nil {
		return nil, err
	}
	transport := newTransport(conn, device, c.Config.Logger)
	done := make(chan error, 1)
	go transport.run(framer, done)

	closeOnError = false
	c.logf("data channel ready: address=%s/%d", assigned, prefixLength)
	return &Tunnel{
		Address: netip.PrefixFrom(assigned, prefixLength),
		MTU:     defaultMTU,
		device:  device,
		closeFn: transport.Close,
		done:    done,
	}, nil
}

func (c *Client) logf(format string, arguments ...any) {
	if c.Config.Logger != nil {
		c.Config.Logger.Printf("[sstp] "+format, arguments...)
	}
}

func setClientHandshakeDeadline(ctx context.Context, conn net.Conn) {
	deadline := time.Now().Add(30 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
}

func clientContextError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}
