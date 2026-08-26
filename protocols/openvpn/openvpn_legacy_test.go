package openvpn

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func TestCompressionFraming(t *testing.T) {
	payload := []byte{0x45, 0, 0, 20}
	plain, err := compressPacket(payload, "")
	if err != nil || !bytes.Equal(plain, payload) {
		t.Fatalf("uncompressed packet = %x, %v", plain, err)
	}
	framed, err := compressPacket(payload, "lzo")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(framed, append([]byte{0xfa}, payload...)) {
		t.Fatalf("framed packet = %x", framed)
	}
	decoded, err := decompressPacket(framed, "lzo")
	if err != nil || !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded packet = %x, %v", decoded, err)
	}
	compressed := append([]byte{0x66, 22}, []byte("hello")...)
	compressed = append(compressed, 0x11, 0, 0)
	decoded, err = decompressPacket(compressed, "lzo")
	if err != nil || string(decoded) != "hello" {
		t.Fatalf("LZO decoded packet = %q, %v", decoded, err)
	}
	if _, err := decompressPacket([]byte{0x66, 1}, "lzo"); err == nil {
		t.Fatal("invalid compressed LZO payload was accepted")
	}
	if _, err := decompressPacket([]byte{0x01, 1}, "lzo"); err == nil {
		t.Fatal("invalid compression marker was accepted")
	}
}

func TestParsePushReplyTopologies(t *testing.T) {
	tests := []struct {
		name  string
		push  string
		bits  int
		valid bool
	}{
		{name: "subnet", push: "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet", bits: 24, valid: true},
		{name: "net30", push: "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,topology net30", bits: 32, valid: true},
		{name: "missing", push: "PUSH_REPLY,route 10.0.0.0 255.0.0.0", valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, bits, err := parsePushReply(test.push)
			if (err == nil) != test.valid {
				t.Fatalf("parsePushReply error = %v", err)
			}
			if err == nil && bits != test.bits {
				t.Fatalf("prefix bits = %d", bits)
			}
		})
	}
}

func TestParsePushOptionsKeepalive(t *testing.T) {
	options, err := parsePushOptions("PUSH_REPLY,ifconfig 172.16.0.3 255.255.0.0,ping 10,ping-restart 60")
	if err != nil {
		t.Fatal(err)
	}
	if options.pingInterval != 10*time.Second || options.pingTimeout != time.Minute {
		t.Fatalf("keepalive = ping %s, timeout %s", options.pingInterval, options.pingTimeout)
	}
}

func TestParsePushOptionsIPv6(t *testing.T) {
	options, err := parsePushOptions("PUSH_REPLY,ifconfig-ipv6 2001:db8:1::2/64 2001:db8:1::1,cipher AES-256-GCM")
	if err != nil {
		t.Fatal(err)
	}
	if options.address.IsValid() || options.address6 != netip.MustParseAddr("2001:db8:1::2") || options.prefixBits6 != 64 {
		t.Fatalf("IPv6 tunnel address = %s/%d", options.address6, options.prefixBits6)
	}
}
