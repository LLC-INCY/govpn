package main

import (
	"flag"
	"os"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/sstp"
)

func main() {
	certPath := flag.String("cert", "server.crt", "server TLS certificate PEM")
	keyPath := flag.String("key", "server.key", "server TLS private key PEM")
	listen := flag.String("listen", "127.0.0.1", "outer TCP listen IP")
	port := flag.Int("port", 4430, "outer TCP listen port")
	user := flag.String("user", "alice", "PPP PAP username")
	password := flag.String("password", "change-me", "PPP PAP password")
	service := flag.String("service", "10.20.0.1:8080", "userspace TCP echo address")
	flag.Parse()

	cert, err := os.ReadFile(*certPath)
	exampleutil.Must(err)
	key, err := os.ReadFile(*keyPath)
	exampleutil.Must(err)
	ctx := exampleutil.Context()
	session, err := sstp.NewServer(sstp.ServerConfig{
		Cert: cert, Key: key, ListenIP: *listen, ListenPort: *port,
		Pool: "10.20.0.0/24", Users: map[string]string{*user: *password},
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	listener, err := session.Listen("tcp", *service)
	exampleutil.Must(err)
	exampleutil.Must(exampleutil.Echo(ctx, listener))
}
