package sstp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	PPPIPv4 = 0x0021
	PPPLCP  = 0xc021
	PPPPAP  = 0xc023
	PPPCHAP = 0xc223
	PPPEAP  = 0xc227
	PPPIPCP = 0x8021

	ConfigureRequest = 1
	ConfigureAck     = 2
	ConfigureNak     = 3
	ConfigureReject  = 4
	TerminateRequest = 5
	TerminateAck     = 6
	EchoRequestCode  = 9
	EchoReplyCode    = 10
)

const (
	LCPOptionMRU            = 1
	LCPOptionAuthentication = 3
	CHAPAlgorithmMSCHAPv2   = 0x81
)

type PPPFrame struct {
	Protocol uint16
	Payload  []byte
}

type ControlFrame struct {
	Code    byte
	ID      byte
	Payload []byte
}

func EncodePPP(protocol uint16, payload []byte) []byte {
	frame := make([]byte, 4+len(payload))
	frame[0], frame[1] = 0xff, 0x03
	binary.BigEndian.PutUint16(frame[2:4], protocol)
	copy(frame[4:], payload)
	return frame
}

func DecodePPP(frame []byte) (PPPFrame, error) {
	if len(frame) >= 2 && frame[0] == 0xff && frame[1] == 0x03 {
		frame = frame[2:]
	}
	if len(frame) == 0 {
		return PPPFrame{}, errors.New("sstp: empty PPP frame")
	}
	if frame[0]&1 != 0 {
		return PPPFrame{Protocol: uint16(frame[0]), Payload: append([]byte(nil), frame[1:]...)}, nil
	}
	if len(frame) < 2 {
		return PPPFrame{}, errors.New("sstp: truncated PPP protocol")
	}
	return PPPFrame{Protocol: binary.BigEndian.Uint16(frame[:2]), Payload: append([]byte(nil), frame[2:]...)}, nil
}

func EncodeControl(code, id byte, payload []byte) []byte {
	result := make([]byte, 4+len(payload))
	result[0], result[1] = code, id
	binary.BigEndian.PutUint16(result[2:4], uint16(len(result)))
	copy(result[4:], payload)
	return result
}

func DecodeControl(payload []byte) (ControlFrame, error) {
	if len(payload) < 4 {
		return ControlFrame{}, errors.New("sstp: truncated PPP control frame")
	}
	length := int(binary.BigEndian.Uint16(payload[2:4]))
	if length < 4 || length > len(payload) {
		return ControlFrame{}, errors.New("sstp: invalid PPP control length")
	}
	return ControlFrame{Code: payload[0], ID: payload[1], Payload: append([]byte(nil), payload[4:length]...)}, nil
}

func EncodePAPRequest(id byte, username, password string) ([]byte, error) {
	if len(username) > 255 || len(password) > 255 {
		return nil, errors.New("sstp: PAP credentials exceed 255 bytes")
	}
	payload := make([]byte, 0, 2+len(username)+len(password))
	payload = append(payload, byte(len(username)))
	payload = append(payload, username...)
	payload = append(payload, byte(len(password)))
	payload = append(payload, password...)
	return EncodeControl(1, id, payload), nil
}

func DecodePAPRequest(payload []byte) (id byte, username, password string, err error) {
	control, err := DecodeControl(payload)
	if err != nil || control.Code != 1 {
		return 0, "", "", errors.New("sstp: invalid PAP authenticate request")
	}
	if len(control.Payload) < 2 || int(control.Payload[0])+1 >= len(control.Payload) {
		return 0, "", "", errors.New("sstp: malformed PAP credentials")
	}
	usernameLength := int(control.Payload[0])
	username = string(control.Payload[1 : 1+usernameLength])
	rest := control.Payload[1+usernameLength:]
	passwordLength := int(rest[0])
	if passwordLength+1 != len(rest) {
		return 0, "", "", errors.New("sstp: malformed PAP password")
	}
	return control.ID, username, string(rest[1:]), nil
}

func EncodePAPResult(success bool, id byte, message string) []byte {
	if len(message) > 255 {
		message = message[:255]
	}
	code := byte(3)
	if success {
		code = 2
	}
	return EncodeControl(code, id, append([]byte{byte(len(message))}, message...))
}

func ParseLCPAuthentication(options []byte) (authentication uint16, algorithm []byte, found bool, err error) {
	for len(options) != 0 {
		if len(options) < 2 {
			return 0, nil, false, errors.New("sstp: truncated LCP option")
		}
		length := int(options[1])
		if length < 2 || length > len(options) {
			return 0, nil, false, errors.New("sstp: invalid LCP option length")
		}
		if options[0] == LCPOptionAuthentication {
			if length < 4 {
				return 0, nil, false, errors.New("sstp: truncated LCP authentication option")
			}
			return binary.BigEndian.Uint16(options[2:4]), append([]byte(nil), options[4:length]...), true, nil
		}
		options = options[length:]
	}
	return 0, nil, false, nil
}

func PAPAuthenticationOption() []byte {
	return []byte{LCPOptionAuthentication, 4, byte(PPPPAP >> 8), byte(PPPPAP & 0xff)}
}

func IPv4Option(address netip.Addr) []byte {
	value := address.As4()
	return []byte{3, 6, value[0], value[1], value[2], value[3]}
}

func ParseIPv4Option(options []byte) (netip.Addr, bool) {
	for len(options) >= 2 {
		length := int(options[1])
		if length < 2 || length > len(options) {
			return netip.Addr{}, false
		}
		if options[0] == 3 && length == 6 {
			return netip.AddrFrom4([4]byte(options[2:6])), true
		}
		options = options[length:]
	}
	return netip.Addr{}, false
}

func ExpectControl(frame PPPFrame, protocol uint16, code byte) (ControlFrame, error) {
	if frame.Protocol != protocol {
		return ControlFrame{}, fmt.Errorf("sstp: got PPP protocol %#x, want %#x", frame.Protocol, protocol)
	}
	control, err := DecodeControl(frame.Payload)
	if err != nil {
		return ControlFrame{}, err
	}
	if control.Code != code {
		return ControlFrame{}, fmt.Errorf("sstp: got PPP code %d, want %d", control.Code, code)
	}
	return control, nil
}
