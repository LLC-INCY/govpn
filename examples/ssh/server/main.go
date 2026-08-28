package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	sshvpn "github.com/bclswl0827/govpn/protocols/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type addressList []string

func (addresses *addressList) String() string { return strings.Join(*addresses, ",") }

func (addresses *addressList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("address cannot be empty")
	}
	*addresses = append(*addresses, value)
	return nil
}

func main() {
	hostKeyPath := flag.String("host-key", "./host_key", "SSH host key; generated when missing")
	listenIP := flag.String("listen", "::", "SSH listen IP")
	port := flag.Int("port", 2222, "SSH listen port")
	username := flag.String("username", "root", "SSH login username")
	password := flag.String("password", "passw0rd", "SSH login password")
	shell := flag.String("shell", "/bin/sh", "shell for PTY sessions on Unix")
	mtu := flag.Int("mtu", 1500, "userspace tunnel MTU")
	service := flag.String("service", "10.90.0.1:8080", "TCP echo service exposed inside each tunnel; empty disables it")
	var addresses addressList
	flag.Var(&addresses, "address", "server tunnel prefix; repeat for IPv4 and IPv6")
	flag.Parse()
	if len(addresses) == 0 {
		addresses = addressList{"10.90.0.1/30", "fd90::1/126"}
	}

	hostKey, err := loadOrCreateHostKey(*hostKeyPath)
	exampleutil.Must(err)
	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
	server := sshvpn.NewServer(sshvpn.ServerConfig{
		HostKey: hostKey,
		Users: map[string]sshvpn.ServerUser{
			*username: {Password: *password},
		},
		Address:           addresses,
		MTU:               *mtu,
		Timeout:           15 * time.Second,
		KeepaliveInterval: 30 * time.Second,
		Logger:            logger,
	})
	exampleutil.Must(registerSessionHandlers(server, *shell, logger))
	exampleutil.Must(server.RegisterSessionRequestHandler("subsystem", sftpHandler(logger)))

	ctx := exampleutil.Context()
	listenAddress := net.JoinHostPort(strings.TrimSpace(*listenIP), fmt.Sprint(*port))
	listener, err := net.Listen("tcp", listenAddress)
	exampleutil.Must(err)
	defer listener.Close()
	logger.Printf("SSH server listening on %s", listener.Addr())
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		rawConnection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Printf("accept SSH connection: %v", acceptErr)
			continue
		}
		go serveConnection(ctx, server, rawConnection, *service, logger)
	}
}

func serveConnection(ctx context.Context, server *sshvpn.Server, rawConnection net.Conn, serviceAddress string, logger *log.Logger) {
	remoteAddress := rawConnection.RemoteAddr()
	err := server.HandleConn(ctx, rawConnection, func(tunnelCtx context.Context, connection *gossh.ServerConn, session *govpn.Session) {
		logger.Printf("tunnel started: user=%s remote=%s addresses=%v", connection.User(), connection.RemoteAddr(), session.Addresses())
		if serviceAddress == "" {
			return
		}
		listener, listenErr := session.Listen("tcp", serviceAddress)
		if listenErr != nil {
			logger.Printf("listen inside tunnel: user=%s error=%v", connection.User(), listenErr)
			return
		}
		if echoErr := exampleutil.Echo(tunnelCtx, listener); echoErr != nil {
			logger.Printf("tunnel service ended: user=%s error=%v", connection.User(), echoErr)
		}
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Printf("SSH connection ended: remote=%s error=%v", remoteAddress, err)
		return
	}
	logger.Printf("SSH connection closed: remote=%s", remoteAddress)
}
