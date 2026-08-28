package main

import (
	"flag"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/softether"
)

func main() {
	server := flag.String("server", "127.0.0.1", "native SoftEther server hostname")
	port := flag.Int("port", 4443, "native SoftEther TLS port")
	hub := flag.String("hub", "DEFAULT", "virtual hub name")
	username := flag.String("username", "alice", "SoftEther username")
	password := flag.String("password", "change-me", "SoftEther password")
	insecure := flag.Bool("insecure-skip-verify", false, "skip TLS certificate verification")
	socks5 := flag.String("socks5", exampleutil.DefaultSOCKS5, "local SOCKS5 listen address")
	flag.Parse()

	ctx := exampleutil.Context()
	session, err := softether.NewClient(softether.Config{
		Server: *server, Port: *port, Hub: *hub, Username: *username,
		Password: *password, SkipVerify: *insecure,
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeClient(ctx, *socks5, session))
}
