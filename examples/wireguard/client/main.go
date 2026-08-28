package main

import (
	"flag"
	"net"
	"strconv"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/wireguard"
)

func main() {
	privateKey := flag.String("private-key", "", "client WireGuard private key")
	serverPublicKey := flag.String("server-public-key", "", "server WireGuard public key")
	server := flag.String("server", "127.0.0.1", "WireGuard server hostname")
	port := flag.Int("port", 51820, "WireGuard server UDP port")
	socks5 := flag.String("socks5", exampleutil.DefaultSOCKS5, "local SOCKS5 listen address")
	flag.Parse()

	ctx := exampleutil.Context()
	session, err := wireguard.NewClient(wireguard.Config{
		PrivateKey: *privateKey,
		Address:    []string{exampleutil.ClientPrefix},
		Peers: []wireguard.Peer{{
			PublicKey:  *serverPublicKey,
			Endpoint:   net.JoinHostPort(*server, strconv.Itoa(*port)),
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}},
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeClient(ctx, *socks5, session))
}
