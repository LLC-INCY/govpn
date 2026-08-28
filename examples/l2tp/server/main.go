package main

import (
	"flag"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/l2tp"
)

func main() {
	listen := flag.String("listen", "0.0.0.0", "outer UDP listen IP")
	public := flag.String("public", "", "public IPv4 address clients use")
	psk := flag.String("psk", "", "IPsec pre-shared key")
	user := flag.String("user", "alice", "PPP MS-CHAPv2 username")
	password := flag.String("password", "change-me", "PPP MS-CHAPv2 password")
	pool := flag.String("pool", "10.20.0.0/24", "inner IPv4 address pool")
	service := flag.String("service", "10.20.0.1:8080", "userspace TCP echo address")
	flag.Parse()

	server, err := l2tp.NewServer(l2tp.ServerConfig{
		ListenIP: *listen,
		PublicIP: *public,
		PSK:      *psk,
		Users:    map[string]string{*user: *password},
		Pool:     *pool,
	})
	exampleutil.Must(err)
	ctx := exampleutil.Context()
	session, err := server.Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	listener, err := session.Listen("tcp", *service)
	exampleutil.Must(err)
	exampleutil.Must(exampleutil.Echo(ctx, listener))
}
