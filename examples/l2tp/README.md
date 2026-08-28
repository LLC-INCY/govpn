# L2TP/IPsec examples

The client and server run IKEv1, NAT-T, ESP transport mode, L2TPv2, PPP
MS-CHAPv2, and IPCP in userspace. They do not create a host TUN device or
modify host routes.

## Client

```sh
go run ./examples/l2tp/client \
  -server vpn.example.com \
  -psk shared-secret \
  -user alice \
  -password secret \
  -service 10.0.0.1:443
```

## Server

The server listens on the standard IKE and NAT-T ports, UDP/500 and UDP/4500.
Binding those ports may require elevated privileges. `-public` must be the
concrete IPv4 address clients use when `-listen` is a wildcard address.

```sh
go run ./examples/l2tp/server \
  -listen 0.0.0.0 \
  -public 203.0.113.10 \
  -psk shared-secret \
  -user alice \
  -password secret \
  -pool 10.20.0.0/24 \
  -service 10.20.0.1:8080
```

After connecting, an L2TP/IPsec client can open `10.20.0.1:8080` to use the
example echo service.
