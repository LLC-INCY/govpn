package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func TestOpenTunnelChannelRequest(t *testing.T) {
	clientConn, serverConn := testTCPPair(t)
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)
	serverResult := make(chan TunnelRequest, 1)
	serverError := make(chan error, 1)

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &gossh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(hostKey)
	go serveTunnelRequest(serverConn, serverConfig, serverResult, serverError)

	connection, channels, requests, err := gossh.NewClientConn(clientConn, "pipe", &gossh.ClientConfig{
		User:            "alice",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := gossh.NewClient(connection, channels, requests)
	t.Cleanup(func() { _ = client.Close() })

	channel, channelRequests, err := openTunnelChannel(client, 7)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = channel.Close() })
	go gossh.DiscardRequests(channelRequests)

	select {
	case request := <-serverResult:
		if request.Mode != sshTunnelModePointToPoint || request.Unit != 7 {
			t.Fatalf("request = %+v", request)
		}
	case err := <-serverError:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for TUN channel request")
	}
}

func serveTunnelRequest(connection net.Conn, config *gossh.ServerConfig, result chan<- TunnelRequest, resultError chan<- error) {
	server, channels, requests, err := gossh.NewServerConn(connection, config)
	if err != nil {
		resultError <- err
		return
	}
	defer server.Close()
	go gossh.DiscardRequests(requests)

	newChannel, ok := <-channels
	if !ok {
		resultError <- fmt.Errorf("SSH connection closed before channel request")
		return
	}
	if newChannel.ChannelType() != "tun@openssh.com" {
		resultError <- fmt.Errorf("channel type = %q", newChannel.ChannelType())
		return
	}
	var request TunnelRequest
	if err := gossh.Unmarshal(newChannel.ExtraData(), &request); err != nil {
		resultError <- err
		return
	}
	channel, channelRequests, err := newChannel.Accept()
	if err != nil {
		resultError <- err
		return
	}
	defer channel.Close()
	go gossh.DiscardRequests(channelRequests)
	result <- request
}

func TestPrepareClientDefaults(t *testing.T) {
	addresses, mtu, server, config, tunnel, err := prepareClient(Config{
		Server:              "ssh.example.com",
		User:                "alice",
		Password:            "secret",
		InsecureSkipHostKey: true,
		Address:             []string{"10.90.0.2/30", "fd90::2/126"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if server != "ssh.example.com:22" {
		t.Fatalf("server = %q", server)
	}
	if mtu != defaultMTU {
		t.Fatalf("MTU = %d, want %d", mtu, defaultMTU)
	}
	if config.Timeout != 15*time.Second {
		t.Fatalf("timeout = %s, want 15s", config.Timeout)
	}
	if tunnel != sshTunnelIDAny {
		t.Fatalf("tunnel = %d, want any", tunnel)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.90.0.2/30"), netip.MustParsePrefix("fd90::2/126")}
	if len(addresses) != len(want) || addresses[0] != want[0] || addresses[1] != want[1] {
		t.Fatalf("addresses = %v, want %v", addresses, want)
	}
}

func TestPrepareClientValidation(t *testing.T) {
	base := Config{
		Server:              "ssh.example.com:22",
		User:                "alice",
		Password:            "secret",
		InsecureSkipHostKey: true,
		Address:             []string{"10.90.0.2/30"},
	}
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{name: "missing server", change: func(c *Config) { c.Server = "" }},
		{name: "missing user", change: func(c *Config) { c.User = "" }},
		{name: "missing address", change: func(c *Config) { c.Address = nil }},
		{name: "invalid address", change: func(c *Config) { c.Address = []string{"invalid"} }},
		{name: "missing auth", change: func(c *Config) { c.Password = "" }},
		{name: "missing host verifier", change: func(c *Config) { c.InsecureSkipHostKey = false }},
		{name: "multiple host verifiers", change: func(c *Config) { c.KnownHostsFile = "known_hosts" }},
		{name: "small MTU", change: func(c *Config) { c.MTU = 575 }},
		{name: "small IPv6 MTU", change: func(c *Config) {
			c.Address = []string{"fd90::2/126"}
			c.MTU = 1279
		}},
		{name: "negative timeout", change: func(c *Config) { c.Timeout = -time.Second }},
		{name: "negative keepalive", change: func(c *Config) { c.KeepaliveInterval = -time.Second }},
		{name: "invalid tunnel", change: func(c *Config) {
			unit := -1
			c.RemoteTunnel = &unit
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.change(&config)
			if _, _, _, _, _, err := prepareClient(config); err == nil {
				t.Fatal("prepareClient succeeded")
			}
		})
	}
}

func TestRemoteTunnelUnit(t *testing.T) {
	unit := 7
	got, err := remoteTunnelUnit(&unit)
	if err != nil {
		t.Fatal(err)
	}
	if got != 7 {
		t.Fatalf("unit = %d, want 7", got)
	}
}
