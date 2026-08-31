package sstp

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bclswl0827/govpn/internal/mschap"
)

// CHAP packet codes (RFC 1994 section 4, extended by RFC 2759).
const (
	CHAPChallenge = 1
	CHAPResponse  = 2
	CHAPSuccess   = 3
	CHAPFailure   = 4
)

// MSCHAPv2ResponseLen is the fixed Value field of an MS-CHAPv2 Response:
// a 16-byte peer challenge, 8 reserved zero bytes, the 24-byte NT response
// and a 1-byte flags field (RFC 2759 section 4).
const MSCHAPv2ResponseLen = 49

// ParseMSCHAPv2Challenge extracts the authenticator challenge and the server
// name from a CHAP Challenge packet body.
//
// The body is a 1-byte Value-Size, the value itself, then the name. Only a
// 16-byte value is valid for MS-CHAPv2.
func ParseMSCHAPv2Challenge(payload []byte) (challenge [mschap.ChallengeLen]byte, name string, err error) {
	if len(payload) < 1 {
		return challenge, "", errors.New("sstp: empty MS-CHAPv2 challenge")
	}
	size := int(payload[0])
	if size != mschap.ChallengeLen {
		return challenge, "", fmt.Errorf("sstp: MS-CHAPv2 challenge value is %d bytes, want %d", size, mschap.ChallengeLen)
	}
	if len(payload) < 1+size {
		return challenge, "", errors.New("sstp: truncated MS-CHAPv2 challenge")
	}
	copy(challenge[:], payload[1:1+size])
	return challenge, string(payload[1+size:]), nil
}

// EncodeMSCHAPv2Response builds the Value + Name body of a CHAP Response.
//
// The layout is peer-challenge(16) || reserved(8 zero) || nt-response(24) ||
// flags(1), preceded by its length and followed by the username.
func EncodeMSCHAPv2Response(peerChallenge [mschap.ChallengeLen]byte, ntResponse [mschap.NTResponseLen]byte, username string) []byte {
	body := make([]byte, 0, 1+MSCHAPv2ResponseLen+len(username))
	body = append(body, MSCHAPv2ResponseLen)
	body = append(body, peerChallenge[:]...)
	body = append(body, make([]byte, 8)...) // reserved, must be zero
	body = append(body, ntResponse[:]...)
	body = append(body, 0) // flags
	body = append(body, username...)
	return body
}

// VerifyMSCHAPv2Success checks the server's Success packet, which carries the
// "S=<40 hex>" authenticator response proving the server also knows the
// password. Without this check a hostile server could accept any password.
func VerifyMSCHAPv2Success(payload []byte, expected string) error {
	message := strings.TrimSpace(string(payload))
	// The message may carry further fields after the authenticator, e.g.
	// "S=... M=Access granted"; compare only the S= field.
	if idx := strings.IndexByte(message, ' '); idx >= 0 {
		message = message[:idx]
	}
	if !strings.EqualFold(message, expected) {
		return errors.New("sstp: server failed MS-CHAPv2 authenticator check")
	}
	return nil
}

// MSCHAPv2FailureMessage renders a CHAP Failure body for logging. The body is
// a human-readable "E=<n> R=<n> ..." string.
func MSCHAPv2FailureMessage(payload []byte) string {
	if msg := strings.TrimSpace(string(payload)); msg != "" {
		return msg
	}
	return "no reason given"
}

// MSCHAPv2AuthenticationOption is the LCP Authentication-Protocol option
// selecting CHAP with the MS-CHAPv2 algorithm, used to Nak a server that
// asked for something we cannot do.
func MSCHAPv2AuthenticationOption() []byte {
	return []byte{LCPOptionAuthentication, 5, byte(PPPCHAP >> 8), byte(PPPCHAP & 0xff), CHAPAlgorithmMSCHAPv2}
}
