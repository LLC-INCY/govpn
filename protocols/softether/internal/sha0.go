package softether

import (
	"encoding/binary"
	"math/bits"
	"strings"
)

// SHA0 implements the original FIPS PUB 180 digest used by SoftEther's
// password challenge. It differs from SHA-1 only in the message schedule.
func SHA0(message []byte) [20]byte {
	length := uint64(len(message)) * 8
	padded := append(append([]byte(nil), message...), 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], length)
	padded = append(padded, size[:]...)
	h0, h1, h2, h3, h4 := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476), uint32(0xc3d2e1f0)
	for len(padded) != 0 {
		var w [80]uint32
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(padded[i*4 : i*4+4])
		}
		for i := 16; i < 80; i++ {
			w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
		}
		a, b, c, d, e := h0, h1, h2, h3, h4
		for i := 0; i < 80; i++ {
			var f, k uint32
			switch {
			case i < 20:
				f, k = (b&c)|(^b&d), 0x5a827999
			case i < 40:
				f, k = b^c^d, 0x6ed9eba1
			case i < 60:
				f, k = (b&c)|(b&d)|(c&d), 0x8f1bbcdc
			default:
				f, k = b^c^d, 0xca62c1d6
			}
			temporary := bits.RotateLeft32(a, 5) + f + e + k + w[i]
			e, d, c, b, a = d, c, bits.RotateLeft32(b, 30), a, temporary
		}
		h0, h1, h2, h3, h4 = h0+a, h1+b, h2+c, h3+d, h4+e
		padded = padded[64:]
	}
	var result [20]byte
	for i, value := range []uint32{h0, h1, h2, h3, h4} {
		binary.BigEndian.PutUint32(result[i*4:i*4+4], value)
	}
	return result
}

func PasswordResponse(username, password string, challenge []byte) [20]byte {
	passwordHash := SHA0([]byte(password + strings.ToUpper(username)))
	material := append(append([]byte(nil), passwordHash[:]...), challenge...)
	return SHA0(material)
}
