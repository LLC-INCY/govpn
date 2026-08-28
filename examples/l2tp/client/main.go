package main

import (
	"flag"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/l2tp"
)

func main() {
	server := flag.String("server", "", "L2TP/IPsec server hostname")
	psk := flag.String("psk", "", "IPsec pre-shared key")
	user := flag.String("user", "", "PPP MS-CHAPv2 username")
	password := flag.String("password", "", "PPP MS-CHAPv2 password")
	service := flag.String("service", "", "TCP service reachable through the VPN")
	flag.Parse()

	ctx := exampleutil.Context()
	session, err := l2tp.NewClient(l2tp.Config{
		Server: *server, PSK: *psk, Username: *user, Password: *password,
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	conn, err := session.DialContext(ctx, "tcp", *service)
	exampleutil.Must(err)
	exampleutil.Must(exampleutil.Interactive(conn))
}
