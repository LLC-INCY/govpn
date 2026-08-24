package openvpn

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
)

func EqualKeySource(a, b KeySource) bool {
	return subtle.ConstantTimeCompare(a.PreMaster[:], b.PreMaster[:]) == 1 &&
		subtle.ConstantTimeCompare(a.Random1[:], b.Random1[:]) == 1 &&
		subtle.ConstantTimeCompare(a.Random2[:], b.Random2[:]) == 1
}

func PutString(w io.Writer, value string) error {
	if value == "" {
		_, err := w.Write([]byte{0, 0})
		return err
	}
	if len(value)+1 > 65535 {
		return errors.New("openvpn: string exceeds uint16 length")
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)+1))
	if _, err := w.Write(length[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, value); err != nil {
		return err
	}
	_, err := w.Write([]byte{0})
	return err
}

func ReadString(r io.Reader, limit int) (string, error) {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(r, lengthBytes[:]); err != nil {
		return "", err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if length == 0 {
		return "", nil
	}
	if length > limit {
		return "", errors.New("openvpn: invalid string length")
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(r, value); err != nil {
		return "", err
	}
	if value[len(value)-1] != 0 {
		return "", errors.New("openvpn: string is not NUL terminated")
	}
	return string(value[:len(value)-1]), nil
}
