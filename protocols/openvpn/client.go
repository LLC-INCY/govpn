package openvpn

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
	protocol "github.com/bclswl0827/govpn/protocols/openvpn/internal"
)

type Client struct{ Config Config }

func NewClient(config Config) *Client { return &Client{Config: config} }

func (c *Client) Start(ctx context.Context) (*govpn.Session, error) {
	config := c.Config
	if err := validateClient(config); err != nil {
		return nil, err
	}
	c.logf("starting client: remotes=%d cipher-list=%s auth=%s compression=%s mtu=%d", len(clientRemotes(config)), strings.Join(effectiveClientDataCiphers(config), ":"), effectiveAuth(config), effectiveCompression(config), effectiveMTU(config.MTU))
	var certificate *tls.Certificate
	if len(config.Cert) != 0 || len(config.Key) != 0 {
		parsed, err := tls.X509KeyPair(config.Cert, config.Key)
		if err != nil {
			return nil, fmt.Errorf("openvpn: client certificate: %w", err)
		}
		certificate = &parsed
	}
	tlsConfig, err := clientTLSConfig(config, certificate)
	if err != nil {
		return nil, err
	}
	c.logf("configuration validated: client-certificate=%t username-password=%t", certificate != nil, config.Username != "" || config.Password != "")
	dialer := net.Dialer{}
	var rawConn net.Conn
	var network string
	var dialErr error
	for _, remote := range clientRemotes(config) {
		candidate := config
		candidate.Remote, candidate.Port = remote.Host, remote.Port
		if remote.Protocol != "" {
			candidate.Protocol = remote.Protocol
		}
		network = transportNetwork(candidate)
		address := net.JoinHostPort(candidate.Remote, strconv.Itoa(candidate.Port))
		c.logf("connecting transport: remote=%s protocol=%s", address, network)
		rawConn, dialErr = dialer.DialContext(ctx, network, address)
		if dialErr == nil {
			config = candidate
			break
		}
		c.logf("transport connection failed: remote=%s error=%v", address, dialErr)
	}
	if rawConn == nil {
		return nil, fmt.Errorf("openvpn: all remote connections failed: %w", dialErr)
	}
	conn := rawConn
	if strings.HasPrefix(network, "tcp") {
		conn = protocol.NewStreamConn(rawConn)
	}
	protectedConn, err := protectClientControl(conn, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	conn = protectedConn
	c.logf("%s transport connected: local=%s remote=%s", network, conn.LocalAddr(), conn.RemoteAddr())
	setHandshakeDeadline(ctx, conn)
	endpoint, err := protocol.ClientEndpoint(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	c.logf("OpenVPN control channel established")
	control := protocol.NewControlConn(endpoint)
	tlsConn := tls.Client(control, tlsConfig)
	c.logf("starting TLS handshake")
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = endpoint.Close()
		return nil, fmt.Errorf("openvpn: TLS handshake: %w", err)
	}
	tlsState := tlsConn.ConnectionState()
	c.logf("TLS handshake completed: version=0x%04x cipher-suite=0x%04x", tlsState.Version, tlsState.CipherSuite)
	_ = conn.SetDeadline(time.Time{})
	clientSource, err := protocol.NewClientKeySource()
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	options := clientOptions(config)
	c.logf("sending key-method authentication")
	if err := protocol.WriteKeyMethod(tlsConn, protocol.KeyMethodMessage{
		Source: clientSource, Options: options, Username: config.Username,
		Password: config.Password, PeerInfo: clientPeerInfo(config),
	}, false); err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	reader := bufio.NewReader(tlsConn)
	serverMessage, err := protocol.ReadKeyMethod(reader, false)
	if err != nil {
		_ = endpoint.Close()
		return nil, fmt.Errorf("openvpn: key-method response: %w", err)
	}
	c.logf("key-method response received")
	c.logf("requesting tunnel parameters")
	if err := protocol.WriteCommand(tlsConn, "PUSH_REQUEST"); err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	pushReply, err := protocol.ReadCommand(reader, 16384)
	if err != nil {
		_ = endpoint.Close()
		return nil, fmt.Errorf("openvpn: PUSH_REPLY: %w", err)
	}
	pushed, err := parsePushOptions(pushReply)
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	allowedCipher := false
	for _, name := range effectiveClientDataCiphers(config) {
		allowedCipher = allowedCipher || normalizeCipherName(name) == pushed.cipher
	}
	if !allowedCipher && normalizeCipherName(config.DataCipherFallback) != pushed.cipher {
		_ = endpoint.Close()
		return nil, fmt.Errorf("openvpn: server selected cipher %s outside data-ciphers", pushed.cipher)
	}
	c.logf("tunnel parameters received: address=%s/%d cipher=%s ping=%s receive-timeout=%s", pushed.address, pushed.prefixBits, pushed.cipher, pushed.pingInterval, pushed.pingTimeout)
	keys := protocol.DeriveKeys(clientSource, serverMessage.Source, endpoint.LocalSessionID(), endpoint.RemoteSessionID())
	sendCipher, err := newDataCipher(pushed.cipher, effectiveAuth(config), keys.Client)
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	receiveCipher, err := newDataCipher(pushed.cipher, effectiveAuth(config), keys.Server)
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	mtu := config.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	device, err := packet.New("openvpn-client", mtu)
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	transport := newTransport(endpoint, device, sendCipher, receiveCipher, config.Compression, pushed.pingInterval, pushed.pingTimeout, config.Logger)
	done := make(chan error, 1)
	go transport.run(done)
	session, err := govpn.NewSession([]netip.Prefix{netip.PrefixFrom(pushed.address, pushed.prefixBits)}, uint32(mtu), device, transport.Close, done)
	if err != nil {
		return nil, err
	}
	c.logf("data channel ready")
	return session, nil
}

func clientRemotes(config Config) []Remote {
	if len(config.Remotes) != 0 {
		return append([]Remote(nil), config.Remotes...)
	}
	return []Remote{{Host: config.Remote, Port: config.Port, Protocol: config.Protocol}}
}

func (c *Client) logf(format string, arguments ...any) {
	if c.Config.Logger != nil {
		c.Config.Logger.Printf("[openvpn] "+format, arguments...)
	}
}
