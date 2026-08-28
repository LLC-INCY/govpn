package l2tp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
	"github.com/bclswl0827/govpn/protocols/l2tp/internal/engine"
	"github.com/bclswl0827/govpn/protocols/l2tp/internal/logutil"
)

type Client struct{ Config Config }

func NewClient(config Config) *Client { return &Client{Config: config} }

func (c *Client) Start(ctx context.Context) (*govpn.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	settings, err := clientSettings(c.Config)
	if err != nil {
		return nil, err
	}
	localIP, err := outboundIP(settings.remote)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, fmt.Errorf("l2tp: bind UDP: %w", err)
	}
	device, err := packet.New("l2tp-client", settings.mtu)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	runContext, cancelRun := context.WithCancel(ctx)
	logger := c.Config.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	client := engine.NewClient(conn, packetIO{ctx: runContext, device: device}, engine.ClientConfig{
		ServerIP: settings.remote.IP,
		IKEPort:  settings.ikePort,
		NATTPort: settings.nattPort,
		LocalIP:  localIP,
		PSK:      []byte(c.Config.PSK),
		Username: c.Config.Username,
		Password: c.Config.Password,
		Logger:   logutil.New(logger),
	})

	closeOnError := true
	defer func() {
		if closeOnError {
			cancelRun()
			_ = client.Close()
			_ = device.Close()
		}
	}()
	handshakeContext, cancelHandshake := context.WithTimeout(runContext, settings.timeout)
	defer cancelHandshake()
	c.logf("starting L2TP/IPsec client: remote=%s:%d", c.Config.Server, settings.ikePort)
	network, err := client.Handshake(handshakeContext)
	if err != nil {
		return nil, fmt.Errorf("l2tp: handshake: %w", err)
	}
	assigned, ok := netip.AddrFromSlice(network.AssignedIP)
	if !ok || !assigned.Is4() {
		return nil, errors.New("l2tp: PPP did not assign an IPv4 address")
	}

	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	closeTransport := func() error {
		cancelRun()
		return client.Close()
	}
	session, err := govpn.NewSession(
		[]netip.Prefix{netip.PrefixFrom(assigned.Unmap(), 32)},
		uint32(settings.mtu), device, closeTransport, done,
	)
	if err != nil {
		return nil, err
	}
	closeOnError = false
	c.logf("data channel ready: address=%s/32", assigned)
	return session, nil
}

type resolvedSettings struct {
	remote            *net.UDPAddr
	ikePort, nattPort int
	mtu               int
	timeout           time.Duration
}

func clientSettings(config Config) (resolvedSettings, error) {
	if config.Server == "" {
		return resolvedSettings{}, errors.New("l2tp: server is required")
	}
	if config.PSK == "" {
		return resolvedSettings{}, errors.New("l2tp: pre-shared key is required")
	}
	if config.Username == "" {
		return resolvedSettings{}, errors.New("l2tp: username is required")
	}
	if config.Password == "" {
		return resolvedSettings{}, errors.New("l2tp: password is required")
	}
	ikePort := config.IKEPort
	if ikePort == 0 {
		ikePort = defaultIKEPort
	}
	if ikePort < 1 || ikePort > 65535 {
		return resolvedSettings{}, errors.New("l2tp: IKE port is out of range")
	}
	remote, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(config.Server, strconv.Itoa(ikePort)))
	if err != nil {
		return resolvedSettings{}, fmt.Errorf("l2tp: resolve server: %w", err)
	}
	mtu := config.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < 576 || mtu > defaultMTU {
		return resolvedSettings{}, fmt.Errorf("l2tp: MTU must be between 576 and %d", defaultMTU)
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return resolvedSettings{remote: remote, ikePort: ikePort, nattPort: defaultNATTPort, mtu: mtu, timeout: timeout}, nil
}

func outboundIP(remote *net.UDPAddr) (net.IP, error) {
	probe, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		return nil, fmt.Errorf("l2tp: route to %s: %w", remote.IP, err)
	}
	defer probe.Close()
	local, ok := probe.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To4() == nil {
		return nil, errors.New("l2tp: cannot determine the local IPv4 address")
	}
	return local.IP.To4(), nil
}

func (c *Client) logf(format string, arguments ...any) {
	if c.Config.Logger != nil {
		c.Config.Logger.Printf("[l2tp] "+format, arguments...)
	}
}

var _ govpn.Client = (*Client)(nil)
