package main

import (
	"flag"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/l2tp"
)

func main() {
	server := flag.String("server", "", "L2TP/IPsec server hostname")
	psk := flag.String("psk", "", "IPsec pre-shared key")
	username := flag.String("username", "alice", "PPP MS-CHAPv2 username")
	password := flag.String("password", "change-me", "PPP MS-CHAPv2 password")
	socks5 := flag.String("socks5", exampleutil.DefaultSOCKS5, "local SOCKS5 listen address")
	flag.Parse()

	ctx := exampleutil.Context()
	session, err := l2tp.NewClient(l2tp.Config{
		Server: *server, PSK: *psk, Username: *username, Password: *password,
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeClient(ctx, *socks5, session))
}
