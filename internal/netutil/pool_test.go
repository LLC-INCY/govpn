package netutil

import "testing"

func TestParseIPv4PoolAddresses(t *testing.T) {
	network, gateway, client, err := ParseIPv4Pool("10.20.0.15/24")
	if err != nil {
		t.Fatal(err)
	}
	if network.String() != "10.20.0.0/24" || gateway.String() != "10.20.0.1" || client.String() != "10.20.0.2" {
		t.Fatalf("addresses = %v, %v, %v; want 10.20.0.0/24, 10.20.0.1, 10.20.0.2", network, gateway, client)
	}
}

func TestParseIPv6PoolAddresses(t *testing.T) {
	network, gateway, client, err := ParseIPv6Pool("fd00::15/64")
	if err != nil {
		t.Fatal(err)
	}
	if network.String() != "fd00::/64" || gateway.String() != "fd00::1" || client.String() != "fd00::2" {
		t.Fatalf("addresses = %v, %v, %v; want fd00::/64, fd00::1, fd00::2", network, gateway, client)
	}
}

func TestParsePoolRejectsInvalidOrSmallPrefix(t *testing.T) {
	for _, test := range []struct {
		name  string
		parse func(string) error
		value string
	}{
		{name: "invalid IPv4", parse: func(value string) error { _, _, _, err := ParseIPv4Pool(value); return err }, value: "invalid"},
		{name: "wrong family", parse: func(value string) error { _, _, _, err := ParseIPv4Pool(value); return err }, value: "fd00::/64"},
		{name: "small IPv4", parse: func(value string) error { _, _, _, err := ParseIPv4Pool(value); return err }, value: "10.20.0.0/31"},
		{name: "small IPv6", parse: func(value string) error { _, _, _, err := ParseIPv6Pool(value); return err }, value: "fd00::/127"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.parse(test.value); err == nil {
				t.Fatal("pool was accepted")
			}
		})
	}
}
