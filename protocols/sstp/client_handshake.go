package sstp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"

	"github.com/bclswl0827/govpn/internal/mschap"
	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

func clientHandshake(framer *protocol.Framer, username, password string, certificateDER []byte, logf func(string, ...any)) (netip.Addr, error) {
	if err := framer.WriteControl(protocol.CallConnectRequest, protocol.Attribute{ID: protocol.AttrEncapsulatedProtocol, Value: []byte{0, protocol.ProtocolPPP}}); err != nil {
		return netip.Addr{}, err
	}
	logf("CALL_CONNECT_REQUEST sent")
	packet, err := framer.ReadPacket()
	if err != nil {
		return netip.Addr{}, err
	}
	if !packet.Control || packet.Message != protocol.CallConnectAck {
		return netip.Addr{}, errors.New("sstp: expected CALL_CONNECT_ACK")
	}
	bindingRequest, ok := protocol.AttributeValue(packet, protocol.AttrCryptoBindingRequest)
	if !ok || len(bindingRequest) != 36 {
		return netip.Addr{}, errors.New("sstp: invalid crypto-binding request")
	}
	hashProtocol := byte(protocol.HashSHA256)
	if bindingRequest[3]&protocol.HashSHA256 == 0 {
		hashProtocol = protocol.HashSHA1
	}
	if bindingRequest[3]&hashProtocol == 0 {
		return netip.Addr{}, errors.New("sstp: server offered no supported certificate hash")
	}
	logf("CALL_CONNECT_ACK received: certificate-hash-mask=%#02x", bindingRequest[3])

	method, err := negotiateClientLCP(framer, logf)
	if err != nil {
		return netip.Addr{}, err
	}
	logf("PPP LCP negotiation completed: authentication=%s", method)

	// hlak is the keying material the crypto binding is computed over. PAP
	// produces none, so it stays nil and CryptoBinding substitutes zeros;
	// MS-CHAPv2 derives it from the exchange (MS-SSTP 3.2.5.2.3).
	var hlak []byte
	switch method {
	case authMSCHAPv2:
		hlak, err = authenticateMSCHAPv2(framer, username, password, logf)
	default:
		err = authenticatePAP(framer, username, password, logf)
	}
	if err != nil {
		return netip.Addr{}, err
	}

	binding, err := protocol.CryptoBinding(hashProtocol, bindingRequest[4:], certificateDER, hlak)
	if err != nil {
		return netip.Addr{}, err
	}
	if err := framer.WriteControl(protocol.CallConnected, protocol.Attribute{ID: protocol.AttrCryptoBinding, Value: binding}); err != nil {
		return netip.Addr{}, err
	}
	logf("CALL_CONNECTED sent")
	return negotiateClientIPCP(framer, logf)
}

// authenticatePAP runs the PAP exchange. The password crosses the wire in the
// clear, protected only by the outer TLS session.
func authenticatePAP(framer *protocol.Framer, username, password string, logf func(string, ...any)) error {
	pap, err := protocol.EncodePAPRequest(2, username, password)
	if err != nil {
		return err
	}
	if err := framer.WriteData(protocol.EncodePPP(protocol.PPPPAP, pap)); err != nil {
		return err
	}
	logf("PPP PAP authentication request sent")
	result, err := readPPP(framer)
	if err != nil {
		return err
	}
	if _, err := protocol.ExpectControl(result, protocol.PPPPAP, 2); err != nil {
		return errors.New("sstp: PAP authentication rejected")
	}
	logf("PPP PAP authentication accepted")
	return nil
}

// authenticateMSCHAPv2 runs the MS-CHAPv2 exchange and returns the 32-byte
// HLAK derived from it.
//
// Beyond proving we know the password, the client also verifies the server's
// authenticator response: without that check any server could accept any
// password. The HLAK ties the PPP authentication to the TLS channel, so a
// wrong value is not rejected here — the server refuses CALL_CONNECTED
// afterwards, which looks like an unexplained disconnect.
func authenticateMSCHAPv2(framer *protocol.Framer, username, password string, logf func(string, ...any)) ([]byte, error) {
	frame, err := readPPP(framer)
	if err != nil {
		return nil, err
	}
	challengeFrame, err := protocol.ExpectControl(frame, protocol.PPPCHAP, protocol.CHAPChallenge)
	if err != nil {
		return nil, fmt.Errorf("sstp: expected MS-CHAPv2 challenge: %w", err)
	}
	authChallenge, serverName, err := protocol.ParseMSCHAPv2Challenge(challengeFrame.Payload)
	if err != nil {
		return nil, err
	}
	logf("PPP MS-CHAPv2 challenge received from %q", serverName)

	var peerChallenge [mschap.ChallengeLen]byte
	if _, err := rand.Read(peerChallenge[:]); err != nil {
		return nil, fmt.Errorf("sstp: generate peer challenge: %w", err)
	}
	ntResponse := mschap.GenerateNTResponse(authChallenge, peerChallenge, username, password)

	body := protocol.EncodeMSCHAPv2Response(peerChallenge, ntResponse, username)
	response := protocol.EncodeControl(protocol.CHAPResponse, challengeFrame.ID, body)
	if err := framer.WriteData(protocol.EncodePPP(protocol.PPPCHAP, response)); err != nil {
		return nil, err
	}
	logf("PPP MS-CHAPv2 response sent")

	result, err := readPPP(framer)
	if err != nil {
		return nil, err
	}
	if result.Protocol != protocol.PPPCHAP {
		return nil, fmt.Errorf("sstp: got PPP protocol %#x during MS-CHAPv2 authentication", result.Protocol)
	}
	control, err := protocol.DecodeControl(result.Payload)
	if err != nil {
		return nil, err
	}
	if control.Code == protocol.CHAPFailure {
		return nil, fmt.Errorf("sstp: MS-CHAPv2 authentication rejected: %s",
			protocol.MSCHAPv2FailureMessage(control.Payload))
	}
	if control.Code != protocol.CHAPSuccess {
		return nil, fmt.Errorf("sstp: unexpected CHAP code %d", control.Code)
	}

	expected := mschap.AuthenticatorResponse(authChallenge, peerChallenge, username, password, ntResponse)
	if err := protocol.VerifyMSCHAPv2Success(control.Payload, expected); err != nil {
		return nil, err
	}
	logf("PPP MS-CHAPv2 authentication accepted")

	hlak := mschap.HLAK(username, password, authChallenge, peerChallenge)
	return hlak[:], nil
}
