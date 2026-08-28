package main

import (
	"flag"
	"os"
	"time"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	sshvpn "github.com/bclswl0827/govpn/protocols/ssh"
)

func main() {
	server := flag.String("server", "127.0.0.1:22", "SSH server address")
	user := flag.String("user", "", "SSH user")
	identity := flag.String("identity", "", "private key file")
	password := flag.String("password", "", "SSH password")
	knownHosts := flag.String("known-hosts", "", "known_hosts file")
	insecureHostKey := flag.Bool("insecure-skip-host-key", false, "disable SSH host key verification")
	address := flag.String("address", "10.90.0.2/30", "local tunnel prefix")
	remoteTunnel := flag.Int("remote-tun", 0, "remote TUN unit")
	remoteCommand := flag.String("remote-command", "", "command to configure the remote TUN")
	service := flag.String("service", "10.90.0.1:8080", "service reached through the tunnel")
	flag.Parse()

	var privateKey []byte
	var err error
	if *identity != "" {
		privateKey, err = os.ReadFile(*identity)
		exampleutil.Must(err)
	}
	ctx := exampleutil.Context()
	session, err := sshvpn.NewClient(sshvpn.Config{
		Server:              *server,
		User:                *user,
		Password:            *password,
		PrivateKey:          privateKey,
		KnownHostsFile:      *knownHosts,
		InsecureSkipHostKey: *insecureHostKey,
		Address:             []string{*address},
		RemoteTunnel:        remoteTunnel,
		RemoteCommand:       *remoteCommand,
		KeepaliveInterval:   30 * time.Second,
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()

	conn, err := session.DialContext(ctx, "tcp", *service)
	exampleutil.Must(err)
	exampleutil.Must(exampleutil.Interactive(conn))
}
