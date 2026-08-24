package main

import (
	"flag"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/wireguard"
)

func main() {
	privateKey := flag.String("private-key", "", "client WireGuard private key")
	serverPublicKey := flag.String("server-public-key", "", "server WireGuard public key")
	endpoint := flag.String("endpoint", "127.0.0.1:51820", "server outer UDP address")
	inner := flag.String("address", "10.10.0.2/24", "client tunnel address")
	service := flag.String("service", "10.10.0.1:8080", "server userspace TCP service")
	flag.Parse()

	ctx := exampleutil.Context()
	session, err := wireguard.NewClient(wireguard.Config{
		PrivateKey: *privateKey,
		Address:    []string{*inner},
		Peers: []wireguard.Peer{{
			PublicKey:  *serverPublicKey,
			Endpoint:   *endpoint,
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}},
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	conn, err := session.DialContext(ctx, "tcp", *service)
	exampleutil.Must(err)
	exampleutil.Must(exampleutil.Interactive(conn))
}
