package main

import (
	"flag"
	"os"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/softether"
)

func main() {
	certPath := flag.String("cert", "server.crt", "server TLS certificate PEM")
	keyPath := flag.String("key", "server.key", "server TLS private key PEM")
	listen := flag.String("listen", "127.0.0.1", "outer TCP listen IP")
	port := flag.Int("port", 4443, "outer TCP listen port")
	hub := flag.String("hub", "DEFAULT", "virtual hub name")
	user := flag.String("user", "alice", "SoftEther username")
	password := flag.String("password", "change-me", "SoftEther password")
	service := flag.String("service", "10.40.0.1:8080", "userspace TCP echo address")
	flag.Parse()

	cert, err := os.ReadFile(*certPath)
	exampleutil.Must(err)
	key, err := os.ReadFile(*keyPath)
	exampleutil.Must(err)
	ctx := exampleutil.Context()
	session, err := softether.NewServer(softether.ServerConfig{
		Cert: cert, Key: key, ListenIP: *listen, ListenPort: *port,
		Hub: *hub, Pool: "10.40.0.0/24", Users: map[string]string{*user: *password},
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	listener, err := session.Listen("tcp", *service)
	exampleutil.Must(err)
	exampleutil.Must(exampleutil.Echo(ctx, listener))
}
