package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (function dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return function(ctx, network, address)
}

func TestDomainConnectAndRelay(t *testing.T) {
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	go func() {
		conn, acceptErr := echoListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	var requestedAddress string
	var requestedNetwork string
	dialer := dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		requestedNetwork = network
		requestedAddress = address
		return (&net.Dialer{}).DialContext(ctx, network, echoListener.Addr().String())
	})
	client, handlerDone := startHandler(t, dialer)
	defer client.Close()
	negotiateTestClient(t, client)

	domain := "example.test"
	request := []byte{version, connectCommand, 0, addressDomain, byte(len(domain))}
	request = append(request, domain...)
	request = binary.BigEndian.AppendUint16(request, 443)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != succeeded {
		t.Fatalf("SOCKS5 reply status = %d", reply[1])
	}
	if requestedAddress != "example.test:443" {
		t.Fatalf("requested address = %q", requestedAddress)
	}
	if requestedNetwork != "tcp4" {
		t.Fatalf("requested network = %q", requestedNetwork)
	}
	payload := []byte("through SOCKS5")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(client, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != string(payload) {
		t.Fatalf("relayed payload = %q", received)
	}
	_ = client.Close()
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 handler did not stop")
	}
}

func TestProxyDialerConnectsThroughSOCKS5(t *testing.T) {
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	go func() {
		conn, acceptErr := echoListener.Accept()
		if acceptErr == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, proxyListener, &net.Dialer{}, nil) }()
	defer proxyListener.Close()

	dialer := ProxyDialer{ProxyAddress: proxyListener.Addr().String(), Transport: &net.Dialer{}}
	conn, err := dialer.DialContext(context.Background(), "tcp", echoListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("through chained SOCKS5")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != string(payload) {
		t.Fatalf("received %q, want %q", received, payload)
	}
}

func TestRejectsUnsupportedCommand(t *testing.T) {
	dialer := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialer called for unsupported command")
		return nil, nil
	})
	client, handlerDone := startHandler(t, dialer)
	defer client.Close()
	negotiateTestClient(t, client)
	request := []byte{version, 2, 0, addressIPv4, 127, 0, 0, 1, 0, 80}
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != commandError {
		t.Fatalf("SOCKS5 reply status = %d", reply[1])
	}
	<-handlerDone
}

func TestRejectsMalformedAddress(t *testing.T) {
	client, handlerDone := startHandler(t, dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialer called for malformed request")
		return nil, nil
	}))
	defer client.Close()
	negotiateTestClient(t, client)
	if _, err := client.Write([]byte{version, connectCommand, 0, 9}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != addressError {
		t.Fatalf("SOCKS5 reply status = %d", reply[1])
	}
	<-handlerDone
}

func startHandler(t *testing.T, dialer Dialer) (net.Conn, <-chan error) {
	t.Helper()
	client, server := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	_ = client.SetDeadline(deadline)
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		done <- handle(context.Background(), server, dialer, nil)
	}()
	return client, done
}

func negotiateTestClient(t *testing.T, client net.Conn) {
	t.Helper()
	if _, err := client.Write([]byte{version, 1, noAuth}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != version || reply[1] != noAuth {
		t.Fatalf("greeting reply = %v", reply)
	}
}
