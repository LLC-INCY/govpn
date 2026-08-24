package wireguard

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

func start(addresses []netip.Prefix, mtu int, uapi string, logger *log.Logger) (*govpn.Session, *Runtime, error) {
	memory, err := packet.New("wireguard", mtu)
	if err != nil {
		return nil, nil, err
	}
	wg := device.NewDevice(memory, conn.NewDefaultBind(), wireGuardLogger(logger))
	transport := &Runtime{device: wg}
	if err := wg.IpcSet(uapi); err != nil {
		transport.Close()
		return nil, nil, fmt.Errorf("wireguard: configure device: %w", err)
	}
	if err := wg.Up(); err != nil {
		transport.Close()
		return nil, nil, fmt.Errorf("wireguard: bring device up: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		<-wg.Wait()
		done <- nil
	}()
	session, err := govpn.NewSession(addresses, uint32(mtu), memory, transport.Close, done)
	if err != nil {
		return nil, nil, err
	}
	return session, transport, nil
}

type Runtime struct {
	device *device.Device
	once   sync.Once
}

func (t *Runtime) Close() error {
	if t == nil || t.device == nil {
		return nil
	}
	t.once.Do(t.device.Close)
	return nil
}

func (t *Runtime) UAPIGet() (string, error) {
	if t == nil || t.device == nil {
		return "", ErrNotStarted
	}
	return t.device.IpcGet()
}

func (t *Runtime) UAPISet(configuration string) error {
	if t == nil || t.device == nil {
		return ErrNotStarted
	}
	return t.device.IpcSet(configuration)
}

func (t *Runtime) Status() (Status, error) {
	configuration, err := t.UAPIGet()
	if err != nil {
		return Status{}, err
	}
	return parseStatus(configuration)
}

func (t *Runtime) ReplacePeers(ctx context.Context, peers []Peer) error {
	prepared, err := preparePeers(ctx, peers)
	if err != nil {
		return err
	}
	var configuration strings.Builder
	configuration.WriteString("replace_peers=true\n")
	if err := appendPeerConfiguration(&configuration, prepared); err != nil {
		return err
	}
	return t.UAPISet(configuration.String())
}

func (t *Runtime) UpdatePeer(ctx context.Context, update PeerUpdate) error {
	var configuration strings.Builder
	if err := appendPeerUpdate(ctx, &configuration, update); err != nil {
		return err
	}
	return t.UAPISet(configuration.String())
}

func (t *Runtime) RemovePeer(publicKey string) error {
	publicHex, err := keyHex(publicKey, false)
	if err != nil {
		return fmt.Errorf("wireguard: peer public key: %w", err)
	}
	return t.UAPISet(fmt.Sprintf("public_key=%s\nremove=true\n", publicHex))
}

func (t *Runtime) SetPrivateKey(privateKey string) error {
	privateHex, err := keyHex(privateKey, false)
	if err != nil {
		return fmt.Errorf("wireguard: private key: %w", err)
	}
	return t.UAPISet("private_key=" + privateHex + "\n")
}

func (t *Runtime) ClearPrivateKey() error {
	return t.UAPISet("private_key=" + strings.Repeat("0", 64) + "\n")
}

func (t *Runtime) SetListenPort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("wireguard: listen port %d is out of range", port)
	}
	return t.UAPISet(fmt.Sprintf("listen_port=%d\n", port))
}

func (t *Runtime) SetFirewallMark(mark uint32) error {
	return t.UAPISet(fmt.Sprintf("fwmark=%d\n", mark))
}

func wireGuardLogger(logger *log.Logger) *device.Logger {
	if logger == nil {
		return device.NewLogger(device.LogLevelSilent, "")
	}
	return &device.Logger{Verbosef: logger.Printf, Errorf: logger.Printf}
}

func normalizedMTU(mtu int) int {
	if mtu == 0 {
		return defaultMTU
	}
	if mtu < 576 || mtu > 65535 {
		return 0
	}
	return mtu
}

func parseAddresses(values []string) ([]netip.Prefix, error) {
	addresses := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("wireguard: address %q: %w", value, err)
		}
		addresses = append(addresses, prefix)
	}
	return addresses, nil
}
