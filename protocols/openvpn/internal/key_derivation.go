package openvpn

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"hash"
	"io"
)

const exportedDataKeyLabel = "EXPORTER-OpenVPN-datakeys"

const keyMaterialSize = 64

type KeySource struct {
	PreMaster [48]byte
	Random1   [32]byte
	Random2   [32]byte
}

type KeyPair struct {
	Cipher [keyMaterialSize]byte
	HMAC   [keyMaterialSize]byte
}

type DataKeys struct {
	Client KeyPair
	Server KeyPair
}

func ExportDataKeys(state *tls.ConnectionState) (DataKeys, error) {
	material, err := state.ExportKeyingMaterial(exportedDataKeyLabel, nil, 4*keyMaterialSize)
	if err != nil {
		return DataKeys{}, fmt.Errorf("openvpn: export TLS data keys: %w", err)
	}
	var keys DataKeys
	offset := 0
	for _, target := range [][]byte{keys.Client.Cipher[:], keys.Client.HMAC[:], keys.Server.Cipher[:], keys.Server.HMAC[:]} {
		copy(target, material[offset:offset+len(target)])
		offset += len(target)
	}
	return keys, nil
}

func NewClientKeySource() (KeySource, error) {
	var source KeySource
	_, err := io.ReadFull(rand.Reader, source.PreMaster[:])
	if err == nil {
		_, err = io.ReadFull(rand.Reader, source.Random1[:])
	}
	if err == nil {
		_, err = io.ReadFull(rand.Reader, source.Random2[:])
	}
	return source, err
}

func NewServerKeySource() (KeySource, error) {
	var source KeySource
	_, err := io.ReadFull(rand.Reader, source.Random1[:])
	if err == nil {
		_, err = io.ReadFull(rand.Reader, source.Random2[:])
	}
	return source, err
}

func DeriveKeys(client, server KeySource, clientSession, serverSession SessionID) DataKeys {
	masterSeed := append([]byte("OpenVPN master secret"), client.Random1[:]...)
	masterSeed = append(masterSeed, server.Random1[:]...)
	master := tls10PRF(client.PreMaster[:], masterSeed, 48)
	expansionSeed := append([]byte("OpenVPN key expansion"), client.Random2[:]...)
	expansionSeed = append(expansionSeed, server.Random2[:]...)
	expansionSeed = append(expansionSeed, clientSession[:]...)
	expansionSeed = append(expansionSeed, serverSession[:]...)
	block := tls10PRF(master, expansionSeed, 4*keyMaterialSize)
	var keys DataKeys
	copy(keys.Client.Cipher[:], block[:64])
	copy(keys.Client.HMAC[:], block[64:128])
	copy(keys.Server.Cipher[:], block[128:192])
	copy(keys.Server.HMAC[:], block[192:256])
	return keys
}

func tls10PRF(secret, seed []byte, length int) []byte {
	half := (len(secret) + 1) / 2
	md5Output := pHash(md5.New, secret[:half], seed, length)
	sha1Output := pHash(sha1.New, secret[len(secret)-half:], seed, length)
	for i := range md5Output {
		md5Output[i] ^= sha1Output[i]
	}
	return md5Output
}

func pHash(digest func() hash.Hash, secret, seed []byte, length int) []byte {
	result := make([]byte, 0, length)
	a := seed
	for len(result) < length {
		mac := hmac.New(digest, secret)
		mac.Write(a)
		a = mac.Sum(nil)
		mac = hmac.New(digest, secret)
		mac.Write(a)
		mac.Write(seed)
		result = append(result, mac.Sum(nil)...)
	}
	return result[:length]
}
