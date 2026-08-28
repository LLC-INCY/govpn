# SSH TUN server example

This example combines the pure-Go `tun@openssh.com` server with the behavior
of `easysshd`:

- concurrent SSH connections;
- an Ed25519 host key generated on first start;
- password authentication;
- Unix PTY shell, terminal resize, and SSH signal forwarding;
- SFTP on Unix and Windows;
- an optional IPv4/IPv6 service inside each userspace tunnel;
- no server-side `/dev/tun` interface.

Start the server:

```sh
go run ./examples/ssh/server \
  -listen :: \
  -port 2222 \
  -username root \
  -password passw0rd \
  -address 10.90.0.1/30 \
  -address fd90::1/126
```

Use the normal SSH and SFTP features without opening a tunnel:

```sh
ssh -p 2222 root@127.0.0.1
sftp -P 2222 root@127.0.0.1
```

Connect with the pure-Go govpn client and reach the example TCP service:

```sh
go run ./examples/ssh/client \
  -server 127.0.0.1:2222 \
  -user root \
  -password passw0rd \
  -insecure-skip-host-key \
  -address 10.90.0.2/30 \
  -service 10.90.0.1:8080
```

SFTP accesses the filesystem with the operating-system permissions of the
server process. The example does not chroot or map SSH usernames to OS users;
production applications should replace the authentication and SFTP handlers
with their own policy.
