package main

import (
	"flag"
	"os"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/openvpn"
)

func main() {
	server := flag.String("server", "127.0.0.1", "OpenVPN server hostname")
	port := flag.Int("port", 1194, "OpenVPN server UDP port")
	caPath := flag.String("ca", "ca.crt", "server CA certificate PEM")
	certPath := flag.String("cert", "client.crt", "client certificate PEM")
	keyPath := flag.String("key", "client.key", "client private key PEM")
	socks5 := flag.String("socks5", exampleutil.DefaultSOCKS5, "local SOCKS5 listen address")
	flag.Parse()

	ca, err := os.ReadFile(*caPath)
	exampleutil.Must(err)
	cert, err := os.ReadFile(*certPath)
	exampleutil.Must(err)
	key, err := os.ReadFile(*keyPath)
	exampleutil.Must(err)
	ctx := exampleutil.Context()
	session, err := openvpn.NewClient(openvpn.Config{
		Remote: *server, Port: *port, CA: ca, Cert: cert, Key: key,
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	exampleutil.Must(exampleutil.ServeClient(ctx, *socks5, session))
}
