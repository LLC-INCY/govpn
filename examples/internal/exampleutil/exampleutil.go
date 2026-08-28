package exampleutil

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"

	"github.com/bclswl0827/govpn/examples/internal/socks5"
)

const (
	InternalCIDR        = "192.168.168.0/24"
	ServerPrefix        = "192.168.168.1/24"
	ClientPrefix        = "192.168.168.2/24"
	HTTPAddress         = "192.168.168.1:80"
	EgressSOCKS5Address = "192.168.168.1:1080"
	DefaultSOCKS5       = "127.0.0.1:1080"
)

var internalNetwork = netip.MustParsePrefix(InternalCIDR)

type Session interface {
	socks5.Dialer
	Listen(network, address string) (net.Listener, error)
}

func Context() context.Context {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	return ctx
}

func ServeServer(ctx context.Context, session Session) error {
	httpListener, err := session.Listen("tcp", HTTPAddress)
	if err != nil {
		return fmt.Errorf("listen HTTP service: %w", err)
	}
	egressListener, err := session.Listen("tcp", EgressSOCKS5Address)
	if err != nil {
		_ = httpListener.Close()
		return fmt.Errorf("listen egress SOCKS5 service: %w", err)
	}
	defer httpListener.Close()
	defer egressListener.Close()
	stop := context.AfterFunc(ctx, func() {
		_ = httpListener.Close()
		_ = egressListener.Close()
	})
	defer stop()

	logger := log.New(os.Stderr, "", log.LstdFlags)
	logger.Printf("HTTP service listening inside VPN on http://%s/", HTTPAddress)
	results := make(chan error, 2)
	go func() {
		handler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = response.Write([]byte("VPN works!"))
		})
		results <- (&http.Server{Handler: handler}).Serve(httpListener)
	}()
	go func() {
		results <- socks5.Serve(ctx, egressListener, &net.Dialer{}, logger)
	}()
	err = <-results
	if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func ServeClient(ctx context.Context, listenAddress string, session Session) error {
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen local SOCKS5: %w", err)
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()

	logger := log.New(os.Stderr, "", log.LstdFlags)
	logger.Printf("SOCKS5 proxy listening on %s", listener.Addr())
	fmt.Fprintf(os.Stderr, "Try `curl --socks5-hostname %s http://%s/`\n", listener.Addr(), HTTPAddress)
	fmt.Fprintf(os.Stderr, "Try `curl --socks5-hostname %s https://github.com/`\n", listener.Addr())
	dialer := routedDialer{
		vpn: session,
		wan: socks5.ProxyDialer{ProxyAddress: EgressSOCKS5Address, Transport: session},
	}
	return socks5.Serve(ctx, listener, dialer, logger)
}

type routedDialer struct {
	vpn socks5.Dialer
	wan socks5.Dialer
}

func (d routedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil && internalNetwork.Contains(ip.Unmap()) {
			return d.vpn.DialContext(ctx, network, address)
		}
	}
	return d.wan.DialContext(ctx, network, address)
}

func Must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
