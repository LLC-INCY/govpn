# govpn

Pure-Go VPN clients and servers backed by a private gVisor network stack.

- WireGuard, SSTP, OpenVPN, and native SoftEther
- no CGO
- no `/dev/tun` or TUN/TAP interface
- no root privileges or host route changes
- TCP and UDP through the standard Go network interfaces

## Install

```sh
go get github.com/bclswl0827/govpn
```

## API

All clients and servers implement the same lifecycle:

```go
type Starter interface {
	Start(context.Context) (*govpn.Session, error)
}
```

A session provides sockets inside the VPN network:

```go
session, err := client.Start(ctx)
if err != nil {
	return err
}
defer session.Close()

conn, err := session.DialContext(ctx, "tcp", "10.0.0.1:443")
listener, err := session.Listen("tcp", "10.0.0.2:8080")
packetConn, err := session.ListenPacket("udp", "10.0.0.2:5353")
```

These sockets are not visible on the host. Use an explicit proxy when a host
application needs access to a session socket.

## WireGuard client

```go
package main

import (
	"context"
	"log"

	"github.com/bclswl0827/govpn/protocols/wireguard"
)

func main() {
	ctx := context.Background()
	client := wireguard.NewClient(wireguard.Config{
		PrivateKey: "CLIENT_PRIVATE_KEY",
		Address:    []string{"10.0.0.2/24"},
		Peers: []wireguard.Peer{{
			PublicKey:  "SERVER_PUBLIC_KEY",
			Endpoint:   "vpn.example.com:51820",
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}},
	})

	session, err := client.Start(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	conn, err := session.DialContext(ctx, "tcp", "10.0.0.1:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}
```

WireGuard configuration files can also be loaded with
`wireguard.ParseConfigFile`. Runtime state and peer updates are available
through `Client.Runtime`, `Client.Status`, and the raw UAPI methods.

## Protocols

| Package               | Implementation                                                                   |
| --------------------- | -------------------------------------------------------------------------------- |
| `protocols/wireguard` | Official `wireguard-go` engine, IPv4/IPv6, PSK, roaming, keepalive, runtime UAPI |
| `protocols/sstp`      | TLS, SSTP, PPP, LCP, PAP, IPCP, crypto binding                                   |
| `protocols/openvpn`   | UDP/TCP, TLS, `tls-auth`, `tls-crypt`, AEAD/CBC ciphers, LZO                     |
| `protocols/softether` | Native SoftEther HTTPS/PACK login and Ethernet data channel                      |

Each package provides `NewClient` and `NewServer`. Complete programs are under
`examples/`:

```sh
go run ./examples/wireguard/client -h
go run ./examples/wireguard/server -h
go run ./examples/sstp/client -h
go run ./examples/openvpn/client -h
go run ./examples/softether/client -h
```

## Limits

- `wg-quick` routes, DNS changes, firewall rules, and lifecycle scripts are
  parsed but not applied to the host.
- SSTP supports PAP authentication; MS-CHAPv2, EAP, and IPv6CP are not yet
  implemented.
- OpenVPN does not provide an IPv6 server address pool.
- SoftEther does not provide UDP acceleration, R-UDP bulk mode, additional TCP
  connections, half connections, or QoS.

Unsupported settings return an error instead of being ignored.

## Test

```sh
CGO_ENABLED=0 go test -buildvcs=false ./...
```

The protocol tests run local userspace client/server pairs. WireGuard also has
direct interoperability tests against the official `wireguard-go` engine.
