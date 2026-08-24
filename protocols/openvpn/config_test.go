package openvpn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConfigFileInline(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "client.ovpn")
	content := "client\nproto udp\nremote vpn.example 443\ndata-ciphers AES-128-GCM:AES-256-GCM\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := ParseConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Remote != "vpn.example" || config.Port != 443 || len(config.DataCiphers) != 2 || config.DataCiphers[0] != "AES-128-GCM" || config.DataCiphers[1] != "AES-256-GCM" || string(config.CA) != "CA\n" {
		t.Fatalf("config = %+v", config)
	}
}

func TestParseConfigFileAuthAndLegacyOptions(t *testing.T) {
	directory := t.TempDir()
	credentialsPath := filepath.Join(directory, "auth.txt")
	if err := os.WriteFile(credentialsPath, []byte("alice\r\nsecret\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "client.ovpn")
	content := "client\nproto udp4\nremote vpn.example 1194\ncipher BF-CBC\nauth-user-pass auth.txt\ncomp-lzo\ntun-mtu 1300\nscript-security 2\n<ca>\nCA\n</ca>\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := ParseConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Username != "alice" || config.Password != "secret" {
		t.Fatal("credentials were not parsed")
	}
	if config.Cipher != "BF-CBC" || config.Compression != "lzo" || config.MTU != 1300 {
		t.Fatalf("legacy options = cipher %q, compression %q, MTU %d", config.Cipher, config.Compression, config.MTU)
	}
}

func TestParseConfigFileRejectsInteractiveAuth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.ovpn")
	if err := os.WriteFile(path, []byte("remote vpn.example\nauth-user-pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseConfigFile(path); err == nil {
		t.Fatal("ParseConfigFile accepted interactive auth-user-pass")
	}
}

func TestParseConfigFileAcceptsTCPAndAES128CBC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.ovpn")
	if err := os.WriteFile(path, []byte("remote vpn.example\nproto tcp-client\ndata-ciphers AES-128-CBC\nauth SHA1\n<ca>\nCA\n</ca>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := ParseConfigFile(path)
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
