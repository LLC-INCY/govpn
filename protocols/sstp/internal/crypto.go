package sstp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
)

const (
	HashSHA1   = 1
	HashSHA256 = 2
)

// CryptoBinding constructs the 100-byte Crypto Binding attribute value from
// MS-SSTP 2.2.7. PAP does not produce keying material, so its HLAK is all zero.
func CryptoBinding(hashProtocol byte, nonce, certificateDER, hlak []byte) ([]byte, error) {
	if len(nonce) != 32 {
		return nil, errors.New("sstp: crypto-binding nonce must be 32 bytes")
	}
	if len(hlak) == 0 {
		hlak = make([]byte, 32)
	}
	if len(hlak) != 32 {
		return nil, errors.New("sstp: HLAK must be 32 bytes")
	}
	var digest func() hash.Hash
	var certificateHash []byte
	switch hashProtocol {
	case HashSHA1:
		digest = sha1.New
		sum := sha1.Sum(certificateDER)
		certificateHash = sum[:]
	case HashSHA256:
		digest = sha256.New
		sum := sha256.Sum256(certificateDER)
		certificateHash = sum[:]
	default:
		return nil, errors.New("sstp: unsupported certificate hash protocol")
	}

	value := make([]byte, 100)
	value[3] = hashProtocol
	copy(value[4:36], nonce)
	copy(value[36:68], certificateHash)

	// CMK = HMAC-HASH(HLAK, seed || little-endian digest size || 0x01).
	keyDerivation := hmac.New(digest, hlak)
	keyDerivation.Write([]byte("SSTP inner method derived CMK"))
	keyDerivation.Write([]byte{byte(keyDerivation.Size()), 0, 1})
	compoundMACKey := keyDerivation.Sum(nil)

	// The MAC covers the complete 112-byte CALL_CONNECTED packet while its
	// compound-MAC field is zero.
	packet := make([]byte, 112)
	packet[0], packet[1], packet[2], packet[3] = Version, 1, 0, 112
	packet[5], packet[7] = CallConnected, 1
	packet[9], packet[10], packet[11] = AttrCryptoBinding, 0, 104
	copy(packet[12:], value)
	mac := hmac.New(digest, compoundMACKey)
	mac.Write(packet)
	copy(value[68:100], mac.Sum(nil))
	return value, nil
}

func VerifyCryptoBinding(value, nonce, certificateDER, hlak []byte) error {
	if len(value) != 100 {
		return errors.New("sstp: crypto-binding value must be 100 bytes")
	}
	if subtle.ConstantTimeCompare(value[4:36], nonce) != 1 {
		return errors.New("sstp: crypto-binding nonce mismatch")
	}
	expected, err := CryptoBinding(value[3], nonce, certificateDER, hlak)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(value, expected) != 1 {
		return errors.New("sstp: crypto-binding verification failed")
	}
	return nil
}
