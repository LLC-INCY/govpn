package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestGenerateKeypair(t *testing.T) {
	private, public, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"private": private, "public": public} {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("%s key = %q, decoded length %d, error %v", name, value, len(decoded), err)
		}
	}
}

func TestValidateAddressMTU(t *testing.T) {
	address4 := netip.MustParsePrefix("192.0.2.2/32")
	address6 := netip.MustParsePrefix("2001:db8::2/128")
	if err := validateAddressMTU([]netip.Prefix{address4}, 1200); err != nil {
		t.Fatalf("IPv4 MTU rejected: %v", err)
	}
	if err := validateAddressMTU([]netip.Prefix{address4, address6}, 1280); err != nil {
		t.Fatalf("minimum IPv6 MTU rejected: %v", err)
	}
	if err := validateAddressMTU([]netip.Prefix{address6}, 1200); err == nil {
		t.Fatal("IPv6 MTU below 1280 accepted")
	}
}

func TestOrderedEndpointAddresses(t *testing.T) {
	address4 := netip.MustParseAddr("192.0.2.1")
	address6 := netip.MustParseAddr("2001:db8::1")
	addresses := []netip.Addr{address6, address4}
	if got := orderedEndpointAddresses(addresses, EndpointPreferenceIPv4); len(got) != 2 || got[0] != address4 || got[1] != address6 {
		t.Fatalf("IPv4 preference = %v", got)
	}
	if got := orderedEndpointAddresses(addresses, EndpointPreferenceIPv6); len(got) != 2 || got[0] != address6 || got[1] != address4 {
		t.Fatalf("IPv6 preference = %v", got)
	}
	if got := orderedEndpointAddresses(addresses, EndpointPreferenceAuto); len(got) != 2 || got[0] != address6 || got[1] != address4 {
		t.Fatalf("automatic preference = %v", got)
	}
	if err := validateEndpointPreference("other"); err == nil {
		t.Fatal("invalid endpoint preference accepted")
	}
}

func TestGeneratePrivateKeyUsesWireGuardClamping(t *testing.T) {
	private, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		t.Fatal(err)
	}
	if decoded[0]&7 != 0 || decoded[31]&0x80 != 0 || decoded[31]&0x40 == 0 {
		t.Fatalf("private key does not have WireGuard X25519 clamping: %x ... %x", decoded[0], decoded[31])
	}
	public, err := PublicKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if decodedPublic, err := base64.StdEncoding.DecodeString(public); err != nil || len(decodedPublic) != 32 {
		t.Fatalf("public key = %q, length=%d, error=%v", public, len(decodedPublic), err)
	}
}

func TestGeneratePresharedKey(t *testing.T) {
	key, err := GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("preshared key length=%d, error=%v", len(decoded), err)
	}
}

func TestBuildUAPI(t *testing.T) {
	private := base64.StdEncoding.EncodeToString(bytesOf(1))
	public := base64.StdEncoding.EncodeToString(bytesOf(2))
	config, err := buildUAPI(private, 51820, []Peer{{
		PublicKey: public, AllowedIPs: []string{"10.0.0.2/32", "2001:db8::2/128"}, Keepalive: 25,
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"private_key=" + strings.Repeat("01", 32),
		"listen_port=51820",
		"public_key=" + strings.Repeat("02", 32),
		"allowed_ip=10.0.0.2/32",
		"allowed_ip=2001:db8::2/128",
		"persistent_keepalive_interval=25",
		"protocol_version=1",
	} {
		if !strings.Contains(config, expected+"\n") {
			t.Errorf("UAPI missing %q:\n%s", expected, config)
		}
	}
}

func TestBuildUAPIAcceptsOfficialPassivePeer(t *testing.T) {
	private := base64.StdEncoding.EncodeToString(bytesOf(1))
	public := base64.StdEncoding.EncodeToString(bytesOf(2))
	configuration, err := buildUAPIWithMark(private, 0, 0x80, []Peer{{PublicKey: public}})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"fwmark=128\n", "replace_allowed_ips=true\n"} {
		if !strings.Contains(configuration, expected) {
			t.Fatalf("UAPI missing %q:\n%s", expected, configuration)
		}
	}
}

func TestAppendPeerUpdateMatchesOfficialUAPI(t *testing.T) {
	public := base64.StdEncoding.EncodeToString(bytesOf(2))
	psk := ""
	endpoint := "192.0.2.1:51820"
	keepalive := 0
	var configuration strings.Builder
	err := appendPeerUpdate(context.Background(), &configuration, PeerUpdate{
		PublicKey: public, UpdateOnly: true, PresharedKey: &psk,
		Endpoint: &endpoint, Keepalive: &keepalive, ReplaceAllowedIPs: true,
		AllowedIPs: []string{"10.0.0.2/32"}, RemoveAllowedIPs: []string{"10.0.0.3/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"update_only=true\n",
		"preshared_key=" + strings.Repeat("0", 64) + "\n",
		"endpoint=192.0.2.1:51820\n",
		"persistent_keepalive_interval=0\n",
		"replace_allowed_ips=true\n",
		"allowed_ip=10.0.0.2/32\n",
		"allowed_ip=-10.0.0.3/32\n",
	} {
		if !strings.Contains(configuration.String(), expected) {
			t.Errorf("UAPI missing %q:\n%s", expected, configuration.String())
		}
	}
}

func TestParseConfigPreservesWGQuickFields(t *testing.T) {
	input := `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/24, 2001:db8::2/64
DNS = 10.0.0.1, corp.example
FwMark = 0xca6c
Table = 1234
PreUp = prepare %i
PostUp = ready %i
PreDown = stopping %i
PostDown = stopped %i
SaveConfig = true

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
EndpointPreference = ipv6
AllowedIPs = 0.0.0.0/0, ::/0
`
	configuration, err := ParseConfig(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if configuration.FirewallMark != 0xca6c || configuration.Table != "1234" || !configuration.SaveConfig ||
		len(configuration.Address) != 2 || len(configuration.DNS) != 2 || len(configuration.PreUp) != 1 ||
		len(configuration.PostUp) != 1 || len(configuration.PreDown) != 1 || len(configuration.PostDown) != 1 ||
		len(configuration.Peers) != 1 || configuration.Peers[0].EndpointPreference != EndpointPreferenceIPv6 {
		t.Fatalf("parsed configuration = %+v", configuration)
	}
}

func TestParseStatus(t *testing.T) {
	privateHex := strings.Repeat("01", 32)
	peerHex := strings.Repeat("02", 32)
	configuration := strings.Join([]string{
		"private_key=" + privateHex,
		"listen_port=51820",
		"fwmark=128",
		"public_key=" + peerHex,
		"preshared_key=" + strings.Repeat("00", 32),
		"protocol_version=1",
		"endpoint=192.0.2.1:51820",
		"last_handshake_time_sec=100",
		"last_handshake_time_nsec=25",
		"tx_bytes=123",
		"rx_bytes=456",
		"persistent_keepalive_interval=25",
		"allowed_ip=10.0.0.0/24",
	}, "\n") + "\n"
	status, err := parseStatus(configuration)
	if err != nil {
		t.Fatal(err)
	}
	peerKey, _ := hex.DecodeString(peerHex)
	if status.ListenPort != 51820 || status.FirewallMark != 128 || status.PublicKey == "" || len(status.Peers) != 1 ||
		status.Peers[0].PublicKey != base64.StdEncoding.EncodeToString(peerKey) || status.Peers[0].Endpoint != "192.0.2.1:51820" ||
		status.Peers[0].Keepalive != 25 || status.Peers[0].TransmitBytes != 123 || status.Peers[0].ReceiveBytes != 456 ||
		!status.Peers[0].LastHandshake.Equal(time.Unix(100, 25)) || len(status.Peers[0].AllowedIPs) != 1 {
		t.Fatalf("status = %+v", status)
	}
}

func TestParseConfigRejectsInvalidNumbers(t *testing.T) {
	for _, input := range []string{
		"[Interface]\nMTU = large\n",
		"[Interface]\nListenPort = nope\n",
		"[Peer]\nPersistentKeepalive = often\n",
		"[Peer]\nEndpointPreference = other\n",
	} {
		if _, err := ParseConfig(strings.NewReader(input)); err == nil {
			t.Fatalf("ParseConfig(%q) succeeded", input)
		}
	}
}

func TestParseConfigAcceptsOfficialOffValues(t *testing.T) {
	configuration, err := ParseConfig(strings.NewReader("[Interface]\nFwMark = off\n[Peer]\nPersistentKeepalive = off\n"))
	if err != nil {
		t.Fatal(err)
	}
	if configuration.FirewallMark != 0 || len(configuration.Peers) != 1 || configuration.Peers[0].Keepalive != 0 {
		t.Fatalf("configuration = %+v", configuration)
	}
}

func bytesOf(value byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = value
	}
	return key
}
