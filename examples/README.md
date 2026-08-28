# govpn examples

Every client/server example uses the same userspace network and application
behavior:

- `192.168.168.0/24` is the VPN network;
- `192.168.168.1` is the server address;
- the server exposes `http://192.168.168.1/` and returns `It works!`;
- the client listens for SOCKS5 on `127.0.0.1:1080` by default;
- public SOCKS5 destinations leave through the VPN server's host network.

After a client connects, it prints commands equivalent to:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://192.168.168.1/
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

The first command verifies access to the server's userspace HTTP service. The
second verifies WAN egress through the server. No host IP forwarding or NAT is
required: public requests are chained to an egress SOCKS5 endpoint reachable
only inside the VPN.

Authentication flags use common names where the protocols have equivalent
concepts: `-username`, `-password`, `-cert`, `-key`, and
`-insecure-skip-verify`. Protocol-specific credentials such as WireGuard keys,
an IPsec PSK, and an SSH host key retain explicit names.

OpenVPN, SSTP, SoftEther, and L2TP obtain `192.168.168.2` from their server-side
configuration protocols. WireGuard and SSH TUN have no address-assignment
exchange, so their examples configure `192.168.168.2/24` statically.
