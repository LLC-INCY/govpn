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

ICMP is available through the same userspace stack. The connection carries
ICMP messages, not host raw sockets:

```go
conn, err := session.DialICMP4("10.0.0.1")
if err != nil {
	return err
}
defer conn.Close()

if err := conn.SetTTL(1); err != nil {
	return err
}
_, err = conn.Write([]byte{8, 0, 0, 0, 0, 1, 0, 1})
```

`ReadFrom` returns the ICMP message and the source IP. Use type 0 replies for
ping and type 11 (IPv4) or type 3 (IPv6) errors for traceroute. IPv4 checksums
are filled automatically. `DialICMP6` and `SetHopLimit` provide the IPv6
equivalent. Traceroute replies from intermediate routers are delivered as
usual. This does not redirect the host `ping` command.

## Host port forwarding

`RegisterPortForward` exposes a host service at the VPN address assigned to the
userspace stack. In this example, the VPN address is `172.20.0.2` and the host
service is `10.0.0.200:8080`.

```go
forward, err := session.RegisterPortForward(ctx, govpn.PortForwardSpec{
	Network:       "tcp4",
	ListenAddress: "172.20.0.2:18080",
	TargetAddress: "10.0.0.200:8080",
})
if err != nil {
	return err
}
defer forward.Close()
```

The remote peer connects to `172.20.0.2:18080`. The listen address belongs to
the userspace VPN stack; the target address is reached through the host
network. Registering a forward does not change host routes, firewall rules, or
DNS settings.

To preserve the host address as the remote destination, use
`ListenAddress: "10.0.0.200:8080"` instead. The VPN peer must then route
`10.0.0.200/32` to this peer.

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
