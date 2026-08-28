package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	sshTunnelModePointToPoint = 1
	sshTunnelIDAny            = 0x7fffffff
	sshTunnelIDMax            = sshTunnelIDAny - 2
	maximumTunnelMTU          = 32 * 1024
)

type Client struct{ Config Config }

func NewClient(config Config) *Client { return &Client{Config: config} }

func (c *Client) Start(ctx context.Context) (*govpn.Session, error) {
	addresses, mtu, server, sshConfig, remoteTunnel, err := prepareClient(c.Config)
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{Timeout: sshConfig.Timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("ssh: connect to %s: %w", server, err)
	}
	closeRaw := true
	defer func() {
		if closeRaw {
			_ = rawConn.Close()
		}
	}()
	stopContextClose := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stopContextClose()

	deadline := time.Now().Add(sshConfig.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := rawConn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("ssh: set startup deadline: %w", err)
	}
	connection, channels, requests, err := gossh.NewClientConn(rawConn, server, sshConfig)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("ssh: handshake: %w", err)
	}
	sshClient := gossh.NewClient(connection, channels, requests)
	closeClient := true
	defer func() {
		if closeClient {
			_ = sshClient.Close()
		}
	}()

	channel, channelRequests, err := openTunnelChannel(sshClient, remoteTunnel)
	if err != nil {
		return nil, fmt.Errorf("ssh: open TUN channel (ensure PermitTunnel point-to-point is enabled): %w", err)
	}
	go gossh.DiscardRequests(channelRequests)
	closeChannel := true
	defer func() {
		if closeChannel {
			_ = channel.Close()
		}
	}()

	if c.Config.RemoteCommand != "" {
		if err := runRemoteCommand(sshClient, c.Config.RemoteCommand); err != nil {
			return nil, err
		}
	}
	if err := rawConn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("ssh: clear startup deadline: %w", err)
	}

	device, err := packet.New("ssh-client", mtu)
	if err != nil {
		return nil, err
	}
	transport := newTransport(sshClient, channel, device, mtu, c.Config.KeepaliveInterval)
	done := make(chan error, 1)
	go transport.run(done)
	session, err := govpn.NewSession(addresses, uint32(mtu), device, transport.Close, done)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	closeRaw = false
	closeClient = false
	closeChannel = false
	stopContextClose()
	c.logf("TUN channel established: server=%s remote-tunnel=%s addresses=%v mtu=%d", server, tunnelUnitString(c.Config.RemoteTunnel), addresses, mtu)
	return session, nil
}

func openTunnelChannel(client *gossh.Client, remoteTunnel uint32) (gossh.Channel, <-chan *gossh.Request, error) {
	return client.OpenChannel("tun@openssh.com", gossh.Marshal(TunnelRequest{
		Mode: sshTunnelModePointToPoint,
		Unit: remoteTunnel,
	}))
}

func prepareClient(config Config) ([]netip.Prefix, int, string, *gossh.ClientConfig, uint32, error) {
	if strings.TrimSpace(config.User) == "" {
		return nil, 0, "", nil, 0, errors.New("ssh: user is required")
	}
	server, err := normalizeServer(config.Server)
	if err != nil {
		return nil, 0, "", nil, 0, err
	}
	addresses, mtu, err := prepareTunnelSettings(TunnelSettings{Address: config.Address, MTU: config.MTU})
	if err != nil {
		return nil, 0, "", nil, 0, err
	}
	auth, err := authenticationMethods(config)
	if err != nil {
		return nil, 0, "", nil, 0, err
	}
	hostKeyCallback, err := hostKeyCallback(config)
	if err != nil {
		return nil, 0, "", nil, 0, err
	}
	remoteTunnel, err := remoteTunnelUnit(config.RemoteTunnel)
	if err != nil {
		return nil, 0, "", nil, 0, err
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	if timeout < 0 {
		return nil, 0, "", nil, 0, errors.New("ssh: timeout cannot be negative")
	}
	if config.KeepaliveInterval < 0 {
		return nil, 0, "", nil, 0, errors.New("ssh: keepalive interval cannot be negative")
	}
	return addresses, mtu, server, &gossh.ClientConfig{
		User: strings.TrimSpace(config.User), Auth: auth, HostKeyCallback: hostKeyCallback, Timeout: timeout,
	}, remoteTunnel, nil
}

func normalizeServer(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("ssh: server is required")
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		parsed, parseErr := strconv.ParseUint(port, 10, 16)
		if host == "" || parseErr != nil || parsed == 0 {
			return "", fmt.Errorf("ssh: invalid server %q", value)
		}
		return net.JoinHostPort(host, port), nil
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return net.JoinHostPort(address.String(), "22"), nil
	}
	if strings.Contains(value, ":") {
		return "", fmt.Errorf("ssh: invalid server %q", value)
	}
	return net.JoinHostPort(value, "22"), nil
}

func parseAddresses(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, errors.New("ssh: at least one tunnel address is required")
	}
	addresses := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		address, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("ssh: invalid tunnel address %q: %w", value, err)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func authenticationMethods(config Config) ([]gossh.AuthMethod, error) {
	methods := make([]gossh.AuthMethod, 0, 2)
	if len(config.PrivateKey) != 0 {
		var signer gossh.Signer
		var err error
		if len(config.PrivateKeyPassphrase) != 0 {
			signer, err = gossh.ParsePrivateKeyWithPassphrase(config.PrivateKey, config.PrivateKeyPassphrase)
		} else {
			signer, err = gossh.ParsePrivateKey(config.PrivateKey)
		}
		if err != nil {
			return nil, fmt.Errorf("ssh: parse private key: %w", err)
		}
		methods = append(methods, gossh.PublicKeys(signer))
	}
	if config.Password != "" {
		methods = append(methods, gossh.Password(config.Password))
	}
	if len(methods) == 0 {
		return nil, errors.New("ssh: password or private key authentication is required")
	}
	return methods, nil
}

func hostKeyCallback(config Config) (gossh.HostKeyCallback, error) {
	configured := 0
	if config.HostKeyCallback != nil {
		configured++
	}
	if config.KnownHostsFile != "" {
		configured++
	}
	if len(config.HostKey) != 0 {
		configured++
	}
	if config.InsecureSkipHostKey {
		configured++
	}
	if configured != 1 {
		return nil, errors.New("ssh: configure exactly one host key verifier")
	}
	if config.HostKeyCallback != nil {
		return config.HostKeyCallback, nil
	}
	if config.KnownHostsFile != "" {
		callback, err := knownhosts.New(config.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("ssh: known_hosts: %w", err)
		}
		return callback, nil
	}
	if len(config.HostKey) != 0 {
		key, _, _, _, err := gossh.ParseAuthorizedKey(config.HostKey)
		if err != nil {
			return nil, fmt.Errorf("ssh: parse host key: %w", err)
		}
		return gossh.FixedHostKey(key), nil
	}
	return gossh.InsecureIgnoreHostKey(), nil
}

func remoteTunnelUnit(value *int) (uint32, error) {
	if value == nil {
		return sshTunnelIDAny, nil
	}
	if *value < 0 || *value > sshTunnelIDMax {
		return 0, fmt.Errorf("ssh: remote tunnel unit %d is out of range", *value)
	}
	return uint32(*value), nil
}

func runRemoteCommand(client *gossh.Client, command string) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh: create remote setup session: %w", err)
	}
	defer session.Close()
	output, err := session.CombinedOutput(command)
	if err != nil {
		return fmt.Errorf("ssh: remote setup command: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func tunnelUnitString(value *int) string {
	if value == nil {
		return "any"
	}
	return strconv.Itoa(*value)
}

func (c *Client) logf(format string, arguments ...any) {
	if c.Config.Logger != nil {
		c.Config.Logger.Printf("[ssh] "+format, arguments...)
	}
}

var _ govpn.Client = (*Client)(nil)
