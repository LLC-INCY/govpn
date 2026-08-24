package main

import (
	"flag"
	"net"
	"strconv"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/wireguard"
)

func main() {
	privateKey := flag.String("private-key", "", "server WireGuard private key")
	peerPublicKey := flag.String("peer-public-key", "", "client WireGuard public key")
	outer := flag.String("listen", ":51820", "outer UDP listen port; official wireguard-go binds wildcard IPv4/IPv6")
	inner := flag.String("address", "10.10.0.1/24", "server tunnel address")
	peerAddress := flag.String("peer-address", "10.10.0.2/32", "client tunnel address")
	service := flag.String("service", "10.10.0.1:8080", "userspace TCP echo address")
	flag.Parse()

	host, portText, err := net.SplitHostPort(*outer)
	exampleutil.Must(err)
	port, err := strconv.Atoi(portText)
	exampleutil.Must(err)
	ctx := exampleutil.Context()
	session, err := wireguard.NewServer(wireguard.ServerConfig{
		PrivateKey: *privateKey,
		ListenIP:   host,
		ListenPort: port,
		Address:    *inner,
		Peers: []wireguard.ServerPeer{{
			PublicKey:  *peerPublicKey,
			AllowedIPs: []string{*peerAddress},
		}},
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	listener, err := session.Listen("tcp", *service)
	exampleutil.Must(err)
	exampleutil.Must(exampleutil.Echo(ctx, listener))
}
