package main

import (
	"flag"

	"github.com/bclswl0827/govpn/examples/internal/exampleutil"
	"github.com/bclswl0827/govpn/protocols/sstp"
)

func main() {
	server := flag.String("server", "127.0.0.1", "SSTP server hostname")
	port := flag.Int("port", 4430, "SSTP server port")
	user := flag.String("user", "alice", "PPP PAP username")
	password := flag.String("password", "change-me", "PPP PAP password")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	service := flag.String("service", "10.20.0.1:8080", "server userspace TCP service")
	flag.Parse()

	ctx := exampleutil.Context()
	session, err := sstp.NewClient(sstp.Config{
		Server: *server, Port: *port, Username: *user, Password: *password, SkipVerify: *insecure,
	}).Start(ctx)
	exampleutil.Must(err)
	defer session.Close()
	conn, err := session.DialContext(ctx, "tcp", *service)
	exampleutil.Must(err)
	exampleutil.Must(exampleutil.Interactive(conn))
}
