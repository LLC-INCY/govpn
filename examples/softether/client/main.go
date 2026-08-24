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
	user := flag.String("user", "alice", "SoftEther username")
	password := flag.String("password", "change-me", "SoftEther password")
	address := flag.String("address", "", "optional static inner prefix; empty uses DHCP inside the virtual Hub")
	gateway := flag.String("gateway", "", "static IPv4 gateway; defaults to the first address in the static subnet")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	service := flag.String("service", "10.40.0.1:8080", "server userspace TCP service")
	flag.Parse()

	ctx := exampleutil.Context()
	session, err := softether.NewClient(softether.Config{
		Server: *server, Port: *port, Hub: *hub, Username: *user,
		Password: *password, Address: *address, Gateway: *gateway, SkipVerify: *insecure,
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	conn, err := session.DialContext(ctx, "tcp", *service)
	exampleutil.Must(err)
	exampleutil.Must(exampleutil.Interactive(conn))
}
