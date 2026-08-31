package sstp

import (
	"log"
	"net"
)

const defaultMTU = 1500

type Config struct {
	Server       string
	Port         int
	Username     string
	Password     string
	CA           []byte
	ServerName   string
	SkipVerify   bool
	PrefixLength int
	Logger       *log.Logger

	// Dialer, when set, establishes the TCP connection the TLS transport is
	// built on. An embedder that runs inside a VPN tunnel needs this to
	// protect the socket (Android VpnService.protect, Apple's NE), otherwise
	// the tunnel's own traffic is routed back into the tunnel it creates.
	// nil uses a plain net.Dialer.
	Dialer *net.Dialer
}

type ServerConfig struct {
	Cert       []byte
	Key        []byte
	ListenIP   string
	ListenPort int
	Pool       string
	DNS        []net.IP
	Users      map[string]string
	// Shape is retained for source compatibility and rejected when non-zero;
	// traffic shaping is not part of SSTP.
	Shape  int
	Logger *log.Logger
}
