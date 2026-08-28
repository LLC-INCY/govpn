package l2tp

import (
	"net"
	"testing"
)

func TestNewServerAcceptsValidConfiguration(t *testing.T) {
	config := ServerConfig{
		ListenIP: "127.0.0.1",
		PSK:      "shared-secret",
		Users:    map[string]string{"alice": "password"},
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	if server.Config.ListenIP != config.ListenIP || server.Config.PSK != config.PSK {
		t.Fatalf("server config = %+v, want %+v", server.Config, config)
	}
}

func TestNewServerValidation(t *testing.T) {
	valid := ServerConfig{
		ListenIP: "127.0.0.1",
		PSK:      "shared-secret",
		Users:    map[string]string{"alice": "password"},
	}
	tests := []struct {
		name   string
		mutate func(*ServerConfig)
	}{
		{name: "missing PSK", mutate: func(config *ServerConfig) { config.PSK = "" }},
		{name: "missing users", mutate: func(config *ServerConfig) { config.Users = nil }},
		{name: "empty username", mutate: func(config *ServerConfig) { config.Users = map[string]string{"": "password"} }},
		{name: "empty password", mutate: func(config *ServerConfig) { config.Users = map[string]string{"alice": ""} }},
		{name: "invalid listen address", mutate: func(config *ServerConfig) { config.ListenIP = "not-an-ip" }},
		{name: "wildcard without public address", mutate: func(config *ServerConfig) { config.ListenIP = "0.0.0.0" }},
		{name: "invalid public address", mutate: func(config *ServerConfig) { config.PublicIP = "not-an-ip" }},
		{name: "invalid IKE port", mutate: func(config *ServerConfig) { config.IKEPort = 65536 }},
		{name: "invalid NAT-T port", mutate: func(config *ServerConfig) { config.NATTPort = -1 }},
		{name: "same ports", mutate: func(config *ServerConfig) { config.IKEPort, config.NATTPort = 4500, 4500 }},
		{name: "invalid pool", mutate: func(config *ServerConfig) { config.Pool = "10.20.0.0/33" }},
		{name: "pool too small", mutate: func(config *ServerConfig) { config.Pool = "10.20.0.0/31" }},
		{name: "MTU too small", mutate: func(config *ServerConfig) { config.MTU = 575 }},
		{name: "MTU too large", mutate: func(config *ServerConfig) { config.MTU = defaultMTU + 1 }},
		{name: "IPv6 DNS", mutate: func(config *ServerConfig) { config.DNS = []net.IP{net.ParseIP("2001:4860:4860::8888")} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := NewServer(config); err == nil {
				t.Fatal("NewServer accepted an invalid configuration")
			}
		})
	}
}

func TestResolveServerSettingsDefaults(t *testing.T) {
	settings, err := resolveServerSettings(ServerConfig{
		ListenIP: "192.0.2.10",
		PSK:      "shared-secret",
		Users:    map[string]string{"alice": "password"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !settings.publicIP.Equal(net.IPv4(192, 0, 2, 10)) {
		t.Errorf("public IP = %v, want 192.0.2.10", settings.publicIP)
	}
	if settings.ikePort != defaultIKEPort || settings.nattPort != defaultNATTPort {
		t.Errorf("ports = %d/%d, want %d/%d", settings.ikePort, settings.nattPort, defaultIKEPort, defaultNATTPort)
	}
	if !settings.gateway.Equal(net.IPv4(10, 20, 0, 1)) || settings.prefixBits != 24 {
		t.Errorf("pool gateway/prefix = %v/%d, want 10.20.0.1/24", settings.gateway, settings.prefixBits)
	}
	if settings.mtu != defaultMTU {
		t.Errorf("MTU = %d, want %d", settings.mtu, defaultMTU)
	}
}

func TestResolveServerSettingsPublicIPForWildcard(t *testing.T) {
	settings, err := resolveServerSettings(ServerConfig{
		ListenIP: "0.0.0.0",
		PublicIP: "198.51.100.5",
		PSK:      "shared-secret",
		Users:    map[string]string{"alice": "password"},
		Pool:     "10.50.0.0/30",
		DNS:      []net.IP{net.IPv4(1, 1, 1, 1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !settings.publicIP.Equal(net.IPv4(198, 51, 100, 5)) {
		t.Errorf("public IP = %v, want 198.51.100.5", settings.publicIP)
	}
	if !settings.gateway.Equal(net.IPv4(10, 50, 0, 1)) || settings.prefixBits != 30 {
		t.Errorf("pool gateway/prefix = %v/%d, want 10.50.0.1/30", settings.gateway, settings.prefixBits)
	}
	if len(settings.dns) != 1 || !settings.dns[0].Equal(net.IPv4(1, 1, 1, 1)) {
		t.Errorf("DNS = %v, want [1.1.1.1]", settings.dns)
	}
}
