package openvpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"strings"

	"golang.org/x/crypto/blowfish"
)

type LegacyDataCipher struct {
	block   cipher.Block
	hmacKey []byte
	digest  func() hash.Hash
	nextID  uint32
	lastID  uint32
	replay  uint64
}

func NewLegacyDataCipher(key KeyPair, auth string) (*LegacyDataCipher, error) {
	return NewCBCDataCipher(key, "BF-CBC", auth)
}

func NewCBCDataCipher(key KeyPair, cipherName, auth string) (*LegacyDataCipher, error) {
	var block cipher.Block
	var err error
	switch {
	case strings.EqualFold(cipherName, "AES-128-CBC"):
		block, err = aes.NewCipher(key.Cipher[:16])
	case strings.EqualFold(cipherName, "AES-192-CBC"):
		block, err = aes.NewCipher(key.Cipher[:24])
	case strings.EqualFold(cipherName, "AES-256-CBC"):
		block, err = aes.NewCipher(key.Cipher[:32])
	case strings.EqualFold(cipherName, "BF-CBC"):
		block, err = blowfish.NewCipher(key.Cipher[:16])
	default:
		return nil, errors.New("openvpn: unsupported CBC data cipher")
	}
	if err != nil {
		return nil, err
	}
	digest := sha1.New
	digestSize := sha1.Size
	switch strings.ToUpper(auth) {
	case "", "SHA1", "SHA-1":
	case "MD5":
		digest, digestSize = md5.New, md5.Size
	case "SHA224", "SHA-224":
		digest, digestSize = sha256.New224, sha256.Size224
	case "SHA256", "SHA-256":
		digest, digestSize = sha256.New, sha256.Size
	case "SHA384", "SHA-384":
		digest, digestSize = sha512.New384, sha512.Size384
	case "SHA512", "SHA-512":
		digest, digestSize = sha512.New, sha512.Size
	default:
		return nil, errors.New("openvpn: unsupported data authentication digest")
	}
	return &LegacyDataCipher{
		block: block, hmacKey: append([]byte(nil), key.HMAC[:digestSize]...),
		digest: digest, nextID: 1,
	}, nil
}

func (c *LegacyDataCipher) Seal(header, plaintext []byte) ([]byte, error) {
	if c.nextID == 0 {
		return nil, errors.New("openvpn: data packet ID exhausted")
	}
	cleartext := make([]byte, 4+len(plaintext))
	binary.BigEndian.PutUint32(cleartext[:4], c.nextID)
	c.nextID++
	copy(cleartext[4:], plaintext)
	blockSize := c.block.BlockSize()
	padding := blockSize - len(cleartext)%blockSize
	cleartext = append(cleartext, make([]byte, padding)...)
	for i := len(cleartext) - padding; i < len(cleartext); i++ {
		cleartext[i] = byte(padding)
	}
	iv := make([]byte, blockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(cleartext))
	cipher.NewCBCEncrypter(c.block, iv).CryptBlocks(ciphertext, cleartext)
	authenticated := append(append([]byte(nil), iv...), ciphertext...)
	mac := hmac.New(c.digest, c.hmacKey)
	_, _ = mac.Write(authenticated)
	result := append(append([]byte(nil), header...), mac.Sum(nil)...)
	return append(result, authenticated...), nil
}

func (c *LegacyDataCipher) Open(_ []byte, payload []byte) ([]byte, error) {
	digestSize := c.digest().Size()
	blockSize := c.block.BlockSize()
	if len(payload) < digestSize+blockSize*2 || (len(payload)-digestSize-blockSize)%blockSize != 0 {
		return nil, errors.New("openvpn: truncated legacy data packet")
	}
	receivedMAC := payload[:digestSize]
	authenticated := payload[digestSize:]
	mac := hmac.New(c.digest, c.hmacKey)
	_, _ = mac.Write(authenticated)
	if subtle.ConstantTimeCompare(receivedMAC, mac.Sum(nil)) != 1 {
		return nil, errors.New("openvpn: legacy data packet authentication failed")
	}
	iv := authenticated[:blockSize]
	ciphertext := authenticated[blockSize:]
	cleartext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(c.block, iv).CryptBlocks(cleartext, ciphertext)
	padding := int(cleartext[len(cleartext)-1])
	if padding == 0 || padding > blockSize || padding > len(cleartext) {
		return nil, errors.New("openvpn: invalid legacy data padding")
	}
	for _, value := range cleartext[len(cleartext)-padding:] {
		if int(value) != padding {
			return nil, errors.New("openvpn: invalid legacy data padding")
		}
	}
	cleartext = cleartext[:len(cleartext)-padding]
	if len(cleartext) < 5 {
		return nil, errors.New("openvpn: legacy data packet has no payload")
	}
	packetID := binary.BigEndian.Uint32(cleartext[:4])
	if packetID == 0 || c.isReplay(packetID) {
		return nil, errors.New("openvpn: replayed data packet")
	}
	c.markReceived(packetID)
	return cleartext[4:], nil
}

func (c *LegacyDataCipher) isReplay(packetID uint32) bool {
	if packetID > c.lastID {
		return false
	}
	distance := c.lastID - packetID
	return distance >= 64 || c.replay&(uint64(1)<<distance) != 0
}

func (c *LegacyDataCipher) markReceived(packetID uint32) {
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
