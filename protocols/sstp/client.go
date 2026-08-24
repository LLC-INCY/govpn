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
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

type Client struct{ Config Config }

func NewClient(config Config) *Client { return &Client{Config: config} }

func (c *Client) Start(ctx context.Context) (*govpn.Session, error) {
	if c.Config.Server == "" {
		return nil, errors.New("sstp: server is required")
	}
	if c.Config.Port <= 0 || c.Config.Port > 65535 {
		return nil, fmt.Errorf("sstp: port %d is out of range", c.Config.Port)
	}
	roots, err := certificatePool(c.Config.CA)
	if err != nil {
		return nil, err
	}
	serverName := c.Config.ServerName
	if serverName == "" {
		serverName = c.Config.Server
	}
	remoteAddress := net.JoinHostPort(c.Config.Server, strconv.Itoa(c.Config.Port))
	c.logf("starting client: remote=%s server-name=%s skip-verify=%t", remoteAddress, serverName, c.Config.SkipVerify)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName, InsecureSkipVerify: c.Config.SkipVerify}
	dialer := tls.Dialer{Config: tlsConfig}
	c.logf("connecting TLS transport")
	conn, err := dialer.DialContext(ctx, "tcp", remoteAddress)
	if err != nil {
		return nil, fmt.Errorf("sstp: TLS dial: %w", err)
	}
	tlsState := conn.(*tls.Conn).ConnectionState()
	c.logf("TLS transport connected: local=%s remote=%s version=0x%04x cipher-suite=0x%04x", conn.LocalAddr(), conn.RemoteAddr(), tlsState.Version, tlsState.CipherSuite)
	setClientHandshakeDeadline(ctx, conn)
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()
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
		return nil, clientContextError(ctx, err)
	}
	reader := bufio.NewReader(conn)
	if err := protocol.ReadServerHTTP(reader); err != nil {
		return nil, clientContextError(ctx, err)
	}
	c.logf("SSTP HTTP tunnel established")
	framer := protocol.NewFramer(reader, conn)
	if len(tlsState.PeerCertificates) == 0 {
		return nil, errors.New("sstp: server sent no certificate")
	}
	c.logf("starting SSTP and PPP negotiation")
	assigned, err := clientHandshake(framer, c.Config.Username, c.Config.Password, tlsState.PeerCertificates[0].Raw, c.logf)
	if err != nil {
		return nil, clientContextError(ctx, err)
	}
	_ = conn.SetDeadline(time.Time{})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
