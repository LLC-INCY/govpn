package main

import (
	"flag"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/sstp"
)

func main() {
	server := flag.String("server", "127.0.0.1", "SSTP server hostname")
	port := flag.Int("port", 4430, "SSTP server port")
	username := flag.String("username", "alice", "PPP PAP username")
	password := flag.String("password", "change-me", "PPP PAP password")
	insecure := flag.Bool("insecure-skip-verify", false, "skip TLS certificate verification")
	socks5 := flag.String("socks5", exampleutil.DefaultSOCKS5, "local SOCKS5 listen address")
	flag.Parse()

	ctx := exampleutil.Context()
	session, err := sstp.NewClient(sstp.Config{
		Server: *server, Port: *port, Username: *username, Password: *password, SkipVerify: *insecure,
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeClient(ctx, *socks5, session))
}
