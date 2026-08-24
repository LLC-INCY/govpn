package main

import (
	"flag"
	"os"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/openvpn"
)

func main() {
	caPath := flag.String("ca", "ca.crt", "client CA certificate PEM")
	certPath := flag.String("cert", "server.crt", "server certificate PEM")
	keyPath := flag.String("key", "server.key", "server private key PEM")
	listen := flag.String("listen", "127.0.0.1", "outer UDP listen IP")
	port := flag.Int("port", 1194, "outer UDP listen port")
	service := flag.String("service", "10.30.0.1:8080", "userspace TCP echo address")
	flag.Parse()

	ca, err := os.ReadFile(*caPath)
	exampleutil.Must(err)
	cert, err := os.ReadFile(*certPath)
	exampleutil.Must(err)
	key, err := os.ReadFile(*keyPath)
	exampleutil.Must(err)
	ctx := exampleutil.Context()
	session, err := openvpn.NewServer(openvpn.ServerConfig{
		CA: ca, Cert: cert, Key: key, ListenIP: *listen, ListenPort: *port, Pool: "10.30.0.0/24",
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	listener, err := session.Listen("tcp", *service)
	exampleutil.Must(err)
	exampleutil.Must(exampleutil.Echo(ctx, listener))
}
