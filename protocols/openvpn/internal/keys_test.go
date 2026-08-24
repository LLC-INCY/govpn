package openvpn

import (
	"bytes"
	"testing"
)

func TestDataCipherRoundTripAndReplay(t *testing.T) {
	var key KeyPair
	for i := range key.Cipher {
		key.Cipher[i] = byte(i)
		key.HMAC[i] = byte(255 - i)
	}
	sender, err := NewDataCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewDataCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	header, _ := DataHeader(DataV1, 0, 0)
	packet, err := sender.Seal(header, []byte("IP packet"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := receiver.Open(header, packet[len(header):])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, []byte("IP packet")) {
		t.Fatalf("plaintext = %q", plaintext)
	}
	if _, err := receiver.Open(header, packet[len(header):]); err == nil {
		t.Fatal("replay accepted")
	}
}

func TestKeyDerivationIsSymmetric(t *testing.T) {
	client, _ := NewClientKeySource()
	server, _ := NewServerKeySource()
	clientID := SessionID{1}
	serverID := SessionID{2}
	a := DeriveKeys(client, server, clientID, serverID)
	b := DeriveKeys(client, server, clientID, serverID)
	if a != b {
		t.Fatal("same key sources produced different key blocks")
	}
}

func TestDataCipherAcceptsReorderedPacketsWithinWindow(t *testing.T) {
	var key KeyPair
	sender, err := NewDataCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewDataCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	header, _ := DataHeader(DataV1, 0, 0)
	first, _ := sender.Seal(header, []byte("first"))
	second, _ := sender.Seal(header, []byte("second"))
	if _, err := receiver.Open(header, second[len(header):]); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Open(header, first[len(header):]); err != nil {
		t.Fatalf("reordered packet rejected: %v", err)
	}
	if _, err := receiver.Open(header, first[len(header):]); err == nil {
		t.Fatal("duplicate reordered packet accepted")
	}
}

func TestAEADDataCiphers(t *testing.T) {
	for _, name := range []string{"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305"} {
		t.Run(name, func(t *testing.T) {
			var key KeyPair
			for i := range key.Cipher {
				key.Cipher[i] = byte(i + 1)
				key.HMAC[i] = byte(255 - i)
			}
			sender, err := NewAEADDataCipher(key, name)
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := NewAEADDataCipher(key, name)
			if err != nil {
				t.Fatal(err)
			}
			header, _ := DataHeader(DataV2, 0, 7)
			sealed, err := sender.Seal(header, []byte("packet"))
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := receiver.Open(header, sealed[len(header):])
			if err != nil {
				t.Fatal(err)
			}
			if string(plaintext) != "packet" {
				t.Fatalf("plaintext = %q", plaintext)
			}
		})
	}
}
