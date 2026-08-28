package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
)

// ESPCrypter protects one direction of the ESP data path.
type ESPCrypter interface {
	Overhead() int
	BlockLen() int
	Seal(destination, additionalData, plaintext []byte) ([]byte, error)
	Open(destination, additionalData, ciphertext []byte) ([]byte, error)
}

func aesKeyLen(keyBits int) (int, error) {
	keyLength := keyBits / 8
	if keyLength == 0 {
		keyLength = 32
	}
	if keyLength != 16 && keyLength != 24 && keyLength != 32 {
		return 0, fmt.Errorf("cryptoutil: invalid AES key length %d bits", keyBits)
	}
	return keyLength, nil
}

// NewAESCBCESPCrypter creates the AES-CBC and HMAC construction used by the
// negotiated IKEv1 ESP transform.
func NewAESCBCESPCrypter(keyBits int, encryptionKey []byte, integrity *Integrity, integrityKey []byte) (ESPCrypter, error) {
	keyLength, err := aesKeyLen(keyBits)
	if err != nil {
		return nil, err
	}
	if len(encryptionKey) < keyLength {
		return nil, errors.New("cryptoutil: CBC key is too short")
	}
	if integrity == nil {
		return nil, errors.New("cryptoutil: CBC ESP requires integrity")
	}
	block, err := aes.NewCipher(encryptionKey[:keyLength])
	if err != nil {
		return nil, err
	}
	return &espCBC{
		block:     block,
		integrity: integrity,
		mac:       integrity.newMAC(integrityKey),
	}, nil
}

type espCBC struct {
	block     cipher.Block
	integrity *Integrity
	mac       hash.Hash
}

func (c *espCBC) Overhead() int { return aes.BlockSize + c.integrity.ICVLen }
func (c *espCBC) BlockLen() int { return aes.BlockSize }

func (c *espCBC) Seal(destination, additionalData, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("cryptoutil: CBC plaintext is not block-aligned")
	}
	start := len(destination)
	destination = append(destination, make([]byte, aes.BlockSize+len(plaintext))...)
	iv := destination[start : start+aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(c.block, iv).CryptBlocks(destination[start+aes.BlockSize:], plaintext)
	c.mac.Reset()
	c.mac.Write(additionalData)
	c.mac.Write(destination[start:])
	destination = append(destination, c.mac.Sum(nil)[:c.integrity.ICVLen]...)
	return destination, nil
}

func (c *espCBC) Open(destination, additionalData, value []byte) ([]byte, error) {
	if len(value) < aes.BlockSize+c.integrity.ICVLen {
		return nil, errors.New("cryptoutil: CBC payload is too short")
	}
	messageEnd := len(value) - c.integrity.ICVLen
	message, receivedMAC := value[:messageEnd], value[messageEnd:]
	c.mac.Reset()
	c.mac.Write(additionalData)
	c.mac.Write(message)
	if subtle.ConstantTimeCompare(c.mac.Sum(nil)[:c.integrity.ICVLen], receivedMAC) != 1 {
		return nil, errors.New("cryptoutil: ESP integrity check failed")
	}
	iv, ciphertext := message[:aes.BlockSize], message[aes.BlockSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("cryptoutil: CBC ciphertext is not block-aligned")
	}
	start := len(destination)
	destination = append(destination, make([]byte, len(ciphertext))...)
	cipher.NewCBCDecrypter(c.block, iv).CryptBlocks(destination[start:], ciphertext)
	return destination, nil
}
