package sstp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bclswl0827/govpn/internal/mschap"
	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

// Drive the client half of the MS-CHAPv2 exchange against a scripted server
// and check both outcomes that matter: the response the client computes, and
// the HLAK it derives for the crypto binding.
func TestAuthenticateMSCHAPv2(t *testing.T) {
	const username, password = "User", "clientPass"
	authChallenge := [mschap.ChallengeLen]byte{
		0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E,
		0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28,
	}

	clientFramer, serverFramer := lcpTestPipe(t)
	type result struct {
		hlak []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		h, err := authenticateMSCHAPv2(clientFramer, username, password, func(string, ...any) {})
		done <- result{h, err}
	}()

	// Server sends the CHAP Challenge.
	body := append([]byte{mschap.ChallengeLen}, authChallenge[:]...)
	body = append(body, "server"...)
	writeTestPPPProto(t, serverFramer, protocol.PPPCHAP, protocol.CHAPChallenge, 7, body)

	// Read the client's Response and recompute it independently.
	frame := readTestPPP(t, serverFramer)
	response, err := protocol.ExpectControl(frame, protocol.PPPCHAP, protocol.CHAPResponse)
	if err != nil {
		t.Fatal(err)
	}
	if response.ID != 7 {
		t.Errorf("response ID = %d, want 7 (must echo the challenge)", response.ID)
	}
	if len(response.Payload) < 1+protocol.MSCHAPv2ResponseLen {
		t.Fatalf("response payload is %d bytes", len(response.Payload))
	}
	if int(response.Payload[0]) != protocol.MSCHAPv2ResponseLen {
		t.Errorf("value-size = %d, want %d", response.Payload[0], protocol.MSCHAPv2ResponseLen)
	}
	var peerChallenge [mschap.ChallengeLen]byte
	copy(peerChallenge[:], response.Payload[1:1+mschap.ChallengeLen])
	// The 8 reserved bytes must be zero (RFC 2759 section 4).
	if !bytes.Equal(response.Payload[17:25], make([]byte, 8)) {
		t.Error("reserved field is not zero")
	}
	var ntResponse [mschap.NTResponseLen]byte
	copy(ntResponse[:], response.Payload[25:25+mschap.NTResponseLen])
	if want := mschap.GenerateNTResponse(authChallenge, peerChallenge, username, password); ntResponse != want {
		t.Error("NT response does not match the expected value")
	}
	if got := string(response.Payload[1+protocol.MSCHAPv2ResponseLen:]); got != username {
		t.Errorf("username = %q", got)
	}

	// Server proves it also knows the password.
	success := mschap.AuthenticatorResponse(authChallenge, peerChallenge, username, password, ntResponse)
	writeTestPPPProto(t, serverFramer, protocol.PPPCHAP, protocol.CHAPSuccess, response.ID, []byte(success))

	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	// The HLAK must be the derived MPPE keys, not zeros — a zero HLAK
	// authenticates fine and then fails CALL_CONNECTED.
	want := mschap.HLAK(username, password, authChallenge, peerChallenge)
	if !bytes.Equal(got.hlak, want[:]) {
		t.Error("HLAK does not match the derived MPPE keys")
	}
	if bytes.Equal(got.hlak, make([]byte, 32)) {
		t.Error("HLAK must not be all zeros for MS-CHAPv2")
	}
}

// A server that accepts the login but returns the wrong authenticator does not
// know the password, so the client must refuse it.
func TestAuthenticateMSCHAPv2RejectsBadAuthenticator(t *testing.T) {
	clientFramer, serverFramer := lcpTestPipe(t)
	done := make(chan error, 1)
	go func() {
		_, err := authenticateMSCHAPv2(clientFramer, "User", "clientPass", func(string, ...any) {})
		done <- err
	}()

	body := append([]byte{mschap.ChallengeLen}, bytes.Repeat([]byte{0xAA}, mschap.ChallengeLen)...)
	writeTestPPPProto(t, serverFramer, protocol.PPPCHAP, protocol.CHAPChallenge, 1, body)
	frame := readTestPPP(t, serverFramer)
	response, err := protocol.ExpectControl(frame, protocol.PPPCHAP, protocol.CHAPResponse)
	if err != nil {
		t.Fatal(err)
	}
	writeTestPPPProto(t, serverFramer, protocol.PPPCHAP, protocol.CHAPSuccess, response.ID,
		[]byte("S="+strings.Repeat("0", 40)))

	if err := <-done; err == nil {
		t.Error("expected the bad authenticator to be rejected")
	}
}

// A CHAP Failure must surface the server's reason rather than a generic error.
func TestAuthenticateMSCHAPv2ReportsFailure(t *testing.T) {
	clientFramer, serverFramer := lcpTestPipe(t)
	done := make(chan error, 1)
	go func() {
		_, err := authenticateMSCHAPv2(clientFramer, "User", "bad", func(string, ...any) {})
		done <- err
	}()

	body := append([]byte{mschap.ChallengeLen}, bytes.Repeat([]byte{0x11}, mschap.ChallengeLen)...)
	writeTestPPPProto(t, serverFramer, protocol.PPPCHAP, protocol.CHAPChallenge, 3, body)
	frame := readTestPPP(t, serverFramer)
	response, err := protocol.ExpectControl(frame, protocol.PPPCHAP, protocol.CHAPResponse)
	if err != nil {
		t.Fatal(err)
	}
	writeTestPPPProto(t, serverFramer, protocol.PPPCHAP, protocol.CHAPFailure, response.ID,
		[]byte("E=691 R=0 C=0 V=3"))

	err = <-done
	if err == nil {
		t.Fatal("expected an authentication failure")
	}
	if !strings.Contains(err.Error(), "E=691") {
		t.Errorf("error should carry the server's reason, got: %v", err)
	}
}

func writeTestPPPProto(t *testing.T, framer *protocol.Framer, proto uint16, code, id byte, payload []byte) {
	t.Helper()
	if err := framer.WriteData(protocol.EncodePPP(proto, protocol.EncodeControl(code, id, payload))); err != nil {
		t.Fatal(err)
	}
}
