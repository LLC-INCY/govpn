package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// ProxyDialer opens connections through a SOCKS5 server reached with
// Transport. It allows a local SOCKS5 server to chain requests through a VPN.
type ProxyDialer struct {
	ProxyAddress string
	Transport    Dialer
}

func (d ProxyDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	if d.Transport == nil {
		return nil, errors.New("SOCKS5 proxy transport is required")
	}
	if d.ProxyAddress == "" {
		return nil, errors.New("SOCKS5 proxy address is required")
	}
	conn, err := d.Transport.DialContext(ctx, "tcp", d.ProxyAddress)
	if err != nil {
		return nil, fmt.Errorf("connect to SOCKS5 proxy: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err = conn.Write([]byte{version, 1, noAuth}); err != nil {
		return nil, err
	}
	greeting := make([]byte, 2)
	if _, err = io.ReadFull(conn, greeting); err != nil {
		return nil, err
	}
	if greeting[0] != version || greeting[1] != noAuth {
		return nil, errors.New("SOCKS5 proxy rejected no-authentication mode")
	}
	request, err := connectRequest(address)
	if err != nil {
		return nil, err
	}
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	if err = readConnectReply(conn); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	closeOnError = false
	return conn, nil
}

func connectRequest(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS5 target %q: %w", address, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS5 target port %q: %w", portText, err)
	}
	request := []byte{version, connectCommand, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, addressIPv4)
			request = append(request, ipv4...)
		} else {
			request = append(request, addressIPv6)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid SOCKS5 target hostname %q", host)
		}
		request = append(request, addressDomain, byte(len(host)))
		request = append(request, host...)
	}
	request = append(request, byte(port>>8), byte(port))
	return request, nil
}

func readConnectReply(conn net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != version || header[2] != 0 {
		return errors.New("invalid SOCKS5 proxy reply")
	}
	if header[1] != succeeded {
		return fmt.Errorf("SOCKS5 proxy connect failed with status %d", header[1])
	}
	addressLength := 0
	switch header[3] {
	case addressIPv4:
		addressLength = net.IPv4len
	case addressIPv6:
		addressLength = net.IPv6len
	case addressDomain:
		length := []byte{0}
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		addressLength = int(length[0])
	default:
		return errors.New("invalid SOCKS5 proxy address type")
	}
	_, err := io.CopyN(io.Discard, conn, int64(addressLength+2))
	return err
}
