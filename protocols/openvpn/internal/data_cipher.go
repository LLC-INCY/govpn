package openvpn

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

type DataCipher struct {
	aead     cipher.AEAD
	implicit [8]byte
	nextID   uint32
	lastID   uint32
	replay   uint64
}

func NewDataCipher(key KeyPair) (*DataCipher, error) {
	return NewAEADDataCipher(key, "AES-256-GCM")
}

// NewAEADDataCipher creates an OpenVPN AEAD data-channel cipher. OpenVPN's
// AEAD packet layout is shared by AES-GCM and ChaCha20-Poly1305: a four-byte
// explicit packet ID, a 16-byte tag, then ciphertext. The remaining eight
// nonce bytes are derived from the key expansion's HMAC material.
func NewAEADDataCipher(key KeyPair, name string) (*DataCipher, error) {
	var aead cipher.AEAD
	var err error
	switch strings.ToUpper(name) {
	case "AES-128-GCM":
		aead, err = newGCM(key.Cipher[:16])
	case "AES-192-GCM":
		aead, err = newGCM(key.Cipher[:24])
	case "AES-256-GCM":
		aead, err = newGCM(key.Cipher[:32])
	case "CHACHA20-POLY1305":
		aead, err = chacha20poly1305.New(key.Cipher[:chacha20poly1305.KeySize])
	default:
		return nil, fmt.Errorf("openvpn: unsupported AEAD data cipher %q", name)
	}
	if err != nil {
		return nil, err
	}
	dataCipher := &DataCipher{aead: aead, nextID: 1}
	copy(dataCipher.implicit[:], key.HMAC[:8])
	return dataCipher, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *DataCipher) Seal(header, plaintext []byte) ([]byte, error) {
	if c.nextID == 0 {
		return nil, errors.New("openvpn: data packet ID exhausted")
	}
	packetID := make([]byte, 4)
	binary.BigEndian.PutUint32(packetID, c.nextID)
	c.nextID++
	nonce := make([]byte, 12)
	copy(nonce, packetID)
	copy(nonce[4:], c.implicit[:])
	additional := append(append([]byte(nil), header...), packetID...)
	sealed := c.aead.Seal(nil, nonce, plaintext, additional)
	tagAtEnd := len(sealed) - c.aead.Overhead()
	result := append(additional, sealed[tagAtEnd:]...)
	result = append(result, sealed[:tagAtEnd]...)
	return result, nil
}

func (c *DataCipher) Open(header, payload []byte) ([]byte, error) {
	if len(payload) < 4+c.aead.Overhead() {
		return nil, errors.New("openvpn: truncated AEAD packet")
	}
	packetID := binary.BigEndian.Uint32(payload[:4])
	if packetID == 0 || c.isReplay(packetID) {
		return nil, errors.New("openvpn: replayed data packet")
	}
	nonce := make([]byte, 12)
	copy(nonce, payload[:4])
	copy(nonce[4:], c.implicit[:])
	additional := append(append([]byte(nil), header...), payload[:4]...)
	tag := payload[4 : 4+c.aead.Overhead()]
	ciphertext := payload[4+c.aead.Overhead():]
	sealed := append(append([]byte(nil), ciphertext...), tag...)
	plaintext, err := c.aead.Open(nil, nonce, sealed, additional)
	if err != nil {
		return nil, err
	}
	c.markReceived(packetID)
	return plaintext, nil
}

func (c *DataCipher) isReplay(packetID uint32) bool {
	if packetID > c.lastID {
		return false
	}
	distance := c.lastID - packetID
	return distance >= 64 || c.replay&(uint64(1)<<distance) != 0
}

func (c *DataCipher) markReceived(packetID uint32) {
	if packetID > c.lastID {
		distance := packetID - c.lastID
		if distance >= 64 {
			c.replay = 0
		} else {
			c.replay <<= distance
		}
		c.lastID = packetID
		c.replay |= 1
		return
	}
	c.replay |= uint64(1) << (c.lastID - packetID)
}
