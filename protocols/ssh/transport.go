package ssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/bclswl0827/govpn/internal/packet"
	transportutil "github.com/bclswl0827/govpn/internal/transport"
	gossh "golang.org/x/crypto/ssh"
)

type transport struct {
	connection        transportConnection
	channel           gossh.Channel
	device            *packet.Device
	mtu               int
	keepaliveInterval time.Duration
	ctx               context.Context
	cancel            context.CancelFunc
	closeConnection   bool
	once              sync.Once
}

type transportConnection interface {
	SendRequest(string, bool, []byte) (bool, []byte, error)
	Close() error
}

func newTransport(connection transportConnection, channel gossh.Channel, device *packet.Device, mtu int, keepaliveInterval time.Duration) *transport {
	ctx, cancel := context.WithCancel(context.Background())
	return newTransportWithContext(connection, channel, device, mtu, keepaliveInterval, ctx, cancel, true)
}

func newTransportWithContext(connection transportConnection, channel gossh.Channel, device *packet.Device, mtu int, keepaliveInterval time.Duration, ctx context.Context, cancel context.CancelFunc, closeConnection bool) *transport {
	return &transport{
		connection: connection, channel: channel, device: device, mtu: mtu,
		keepaliveInterval: keepaliveInterval, ctx: ctx, cancel: cancel,
		closeConnection: closeConnection,
	}
}

func (t *transport) Close() error {
	var err error
	t.once.Do(func() {
		t.cancel()
		connectionErr := error(nil)
		if t.closeConnection {
			connectionErr = t.connection.Close()
		}
		err = errors.Join(t.channel.Close(), connectionErr, t.device.Close())
	})
	return err
}

func (t *transport) run(done chan<- error) {
	errCh := make(chan error, 3)
	go t.sendPackets(t.ctx, errCh)
	go t.receivePackets(t.ctx, errCh)
	if t.keepaliveInterval > 0 {
		go t.keepalive(t.ctx, errCh)
	}
	err := <-errCh
	_ = t.Close()
	err = transportutil.NormalizeError(err)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	done <- err
}

func (t *transport) sendPackets(ctx context.Context, errCh chan<- error) {
	for {
		value, err := t.device.ReadPacket(ctx)
		if err == nil {
			if len(value) == 0 || len(value) > t.mtu {
				err = fmt.Errorf("ssh: outbound IP packet length %d exceeds MTU %d", len(value), t.mtu)
			} else if written, writeErr := t.channel.Write(value); writeErr != nil {
				err = writeErr
			} else if written != len(value) {
				err = io.ErrShortWrite
			}
		}
		if err != nil {
			errCh <- err
			return
		}
	}
}

func (t *transport) receivePackets(ctx context.Context, errCh chan<- error) {
	reader := bufio.NewReaderSize(t.channel, t.mtu*2)
	for {
		value, err := readIPPacket(reader, t.mtu)
		if err == nil {
			err = t.device.WritePacket(ctx, value)
		}
		if err != nil {
			errCh <- err
			return
		}
	}
}

func (t *transport) keepalive(ctx context.Context, errCh chan<- error) {
	ticker := time.NewTicker(t.keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, _, err := t.connection.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				errCh <- err
				return
			}
		}
	}
}
