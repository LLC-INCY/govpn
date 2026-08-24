package openvpn

import (
	"bytes"
	"testing"
)

func TestLegacyDataCipherRoundTrip(t *testing.T) {
	for _, auth := range []string{"SHA1", "SHA256"} {
		t.Run(auth, func(t *testing.T) {
			key := legacyTestKey()
			sender, err := NewLegacyDataCipher(key, auth)
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := NewLegacyDataCipher(key, auth)
			if err != nil {
				t.Fatal(err)
			}
			header := []byte{DataV1 << 3}
			payload := []byte("legacy OpenVPN payload")
			packet, err := sender.Seal(header, payload)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := receiver.Open(packet[:1], packet[1:])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, payload) {
				t.Fatalf("plaintext = %q", plaintext)
			}
		})
	}
}

func TestAES128CBCDataCipherRoundTrip(t *testing.T) {
	key := legacyTestKey()
	sender, err := NewCBCDataCipher(key, "AES-128-CBC", "SHA1")
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewCBCDataCipher(key, "AES-128-CBC", "SHA1")
	if err != nil {
		t.Fatal(err)
	}
	header := []byte{DataV1 << 3}
	payload := []byte("AES CBC OpenVPN payload")
	packet, err := sender.Seal(header, payload)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := receiver.Open(packet[:1], packet[1:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestLegacyDataCipherRejectsTamperingAndReplay(t *testing.T) {
	key := legacyTestKey()
	sender, err := NewLegacyDataCipher(key, "SHA1")
	if err != nil {
		t.Fatal(err)
	}
	header := []byte{DataV1 << 3}
	packet, err := sender.Seal(header, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), packet...)
	tampered[len(tampered)-1] ^= 1
	receiver, err := NewLegacyDataCipher(key, "SHA1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Open(tampered[:1], tampered[1:]); err == nil {
		t.Fatal("tampered packet was accepted")
	}
	if _, err := receiver.Open(packet[:1], packet[1:]); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Open(packet[:1], packet[1:]); err == nil {
		t.Fatal("replayed packet was accepted")
	}
}

func TestCBCDataCiphersAndDigests(t *testing.T) {
	key := legacyTestKey()
	for _, cipherName := range []string{"AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "BF-CBC"} {
		for _, auth := range []string{"MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"} {
			t.Run(cipherName+"/"+auth, func(t *testing.T) {
				sender, err := NewCBCDataCipher(key, cipherName, auth)
				if err != nil {
					t.Fatal(err)
				}
				receiver, err := NewCBCDataCipher(key, cipherName, auth)
				if err != nil {
					t.Fatal(err)
				}
				header, _ := DataHeader(DataV1, 0, 0)
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
}

func legacyTestKey() KeyPair {
	var key KeyPair
	for index := range key.Cipher {
		key.Cipher[index] = byte(index + 1)
		key.HMAC[index] = byte(255 - index)
	}
	return key
}
