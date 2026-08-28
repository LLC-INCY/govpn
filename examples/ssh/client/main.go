package main

import (
	"flag"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	sshvpn "github.com/bclswl0827/govpn/protocols/ssh"
)

func main() {
	server := flag.String("server", "127.0.0.1", "SSH server hostname")
	port := flag.Int("port", 2222, "SSH server port")
	username := flag.String("username", "root", "SSH username")
	privateKeyPath := flag.String("private-key", "", "SSH private key file")
	password := flag.String("password", "passw0rd", "SSH password")
	knownHosts := flag.String("known-hosts", "", "known_hosts file")
	insecureHostKey := flag.Bool("insecure-skip-verify", false, "disable SSH host key verification")
	remoteTunnel := flag.Int("remote-tun", 0, "remote TUN unit")
	remoteCommand := flag.String("remote-command", "", "command to configure the remote TUN")
	socks5 := flag.String("socks5", exampleutil.DefaultSOCKS5, "local SOCKS5 listen address")
	flag.Parse()

	var privateKey []byte
	var err error
	if *privateKeyPath != "" {
		privateKey, err = os.ReadFile(*privateKeyPath)
		exampleutil.Must(err)
	}
	ctx := exampleutil.Context()
	session, err := sshvpn.NewClient(sshvpn.Config{
		Server:              net.JoinHostPort(*server, strconv.Itoa(*port)),
		User:                *username,
		Password:            *password,
		PrivateKey:          privateKey,
		KnownHostsFile:      *knownHosts,
		InsecureSkipHostKey: *insecureHostKey,
		Address:             []string{exampleutil.ClientPrefix},
		RemoteTunnel:        remoteTunnel,
		RemoteCommand:       *remoteCommand,
		KeepaliveInterval:   30 * time.Second,
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeClient(ctx, *socks5, session))
}
