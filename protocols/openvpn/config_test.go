package openvpn

import (
	"testing"
)

func TestParseConfigInline(t *testing.T) {
	content := "client\nproto udp\nremote vpn.example 443\ndata-ciphers AES-128-GCM:AES-256-GCM\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"
	config, err := ParseConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if config.Remote != "vpn.example" || config.Port != 443 || len(config.DataCiphers) != 2 || config.DataCiphers[0] != "AES-128-GCM" || config.DataCiphers[1] != "AES-256-GCM" || string(config.CA) != "CA\n" {
		t.Fatalf("config = %+v", config)
	}
}

func TestParseConfigIgnoresAuthUserPassAndParsesLegacyOptions(t *testing.T) {
	content := "client\nproto udp4\nremote vpn.example 1194\ncipher BF-CBC\nauth-user-pass missing-file\ncomp-lzo\ntun-mtu 1300\nscript-security 2\n<ca>\nCA\n</ca>\n"
	config, err := ParseConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if config.Username != "" || config.Password != "" {
		t.Fatal("auth-user-pass credentials were parsed")
	}
	if config.Cipher != "BF-CBC" || config.Compression != "lzo" || config.MTU != 1300 {
		t.Fatalf("legacy options = cipher %q, compression %q, MTU %d", config.Cipher, config.Compression, config.MTU)
	}
}

func TestParseConfigIgnoresInteractiveAndInlineAuthUserPass(t *testing.T) {
	for _, value := range []string{
		"remote vpn.example\nauth-user-pass\n",
		"remote vpn.example\n<auth-user-pass>\nalice\nsecret\n</auth-user-pass>\n",
	} {
		config, err := ParseConfig([]byte(value))
		if err != nil {
			t.Fatal(err)
		}
		if config.Username != "" || config.Password != "" {
			t.Fatal("auth-user-pass credentials were parsed")
		}
	}
}

func TestParseConfigIgnoresDHCPOption(t *testing.T) {
	config, err := ParseConfig([]byte("remote vpn.example\ndhcp-option DNS 1.1.1.1\ndhcp-option DOMAIN vpn.example\nroute-delay 5\nroute 10.0.0.0 255.0.0.0\n<connection>\nremote backup.example\n</connection>\n"))
	if err != nil {
		t.Fatal(err)
	}
	if config.Remote != "vpn.example" {
		t.Fatalf("remote = %q", config.Remote)
	}
	want := []string{"dhcp-option", "route-delay", "route", "connection"}
	if len(config.IgnoredDirectives) != len(want) {
		t.Fatalf("ignored directives = %v", config.IgnoredDirectives)
	}
	for index := range want {
		if config.IgnoredDirectives[index] != want[index] {
			t.Fatalf("ignored directives = %v", config.IgnoredDirectives)
		}
	}
}

func TestParseConfigAcceptsTCPAndAES128CBC(t *testing.T) {
	value := []byte("remote vpn.example\nproto tcp-client\ndata-ciphers AES-128-CBC\nauth SHA1\n<ca>\nCA\n</ca>\n")
	config, err := ParseConfig(value)
	if err != nil {
		t.Fatal(err)
	}
	if config.Protocol != "tcp" || len(config.DataCiphers) != 1 || config.DataCiphers[0] != "AES-128-CBC" || config.Auth != "SHA1" {
		t.Fatalf("config = %+v", config)
	}
}

func TestParseDataCiphersPreservesPreferenceAndOptionalEntries(t *testing.T) {
	parsed, err := parseDataCipherList("AES-128-GCM:?UNAVAILABLE:CHACHA20-POLY1305:AES-128-GCM")
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 2 || parsed[0] != "AES-128-GCM" || parsed[1] != "CHACHA20-POLY1305" {
		t.Fatalf("data ciphers = %v", parsed)
	}
}

func TestSelectDataCipherUsesServerPreference(t *testing.T) {
	selected, err := selectDataCipher(
		[]string{"CHACHA20-POLY1305", "AES-256-GCM"},
		[]string{"AES-256-GCM", "CHACHA20-POLY1305"},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if selected != "CHACHA20-POLY1305" {
		t.Fatalf("selected cipher = %q", selected)
	}
}

func TestLegacyCipherDoesNotDisableDefaultDataCiphers(t *testing.T) {
	ciphers := effectiveClientDataCiphers(Config{Cipher: "AES-128-CBC"})
	want := []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-128-CBC"}
	if len(ciphers) != len(want) {
		t.Fatalf("data ciphers = %v", ciphers)
	}
	for index := range want {
		if ciphers[index] != want[index] {
			t.Fatalf("data ciphers = %v", ciphers)
		}
	}
}
