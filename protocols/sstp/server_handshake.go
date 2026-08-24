package sstp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

func serverHandshake(framer *protocol.Framer, users map[string]string, assigned netip.Addr, certificateDER []byte) error {
	request, err := framer.ReadPacket()
	if err != nil {
		return err
	}
	encapsulation, ok := protocol.AttributeValue(request, protocol.AttrEncapsulatedProtocol)
	if !request.Control || request.Message != protocol.CallConnectRequest || !ok || len(encapsulation) != 2 || binary.BigEndian.Uint16(encapsulation) != protocol.ProtocolPPP {
		return errors.New("sstp: invalid CALL_CONNECT_REQUEST")
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	bindingRequest := append([]byte{0, 0, 0, protocol.HashSHA1 | protocol.HashSHA256}, nonce...)
	if err := framer.WriteControl(protocol.CallConnectAck, protocol.Attribute{ID: protocol.AttrCryptoBindingRequest, Value: bindingRequest}); err != nil {
		return err
	}
	if err := negotiateServerLCP(framer); err != nil {
		return err
	}
	authFrame, err := readPPP(framer)
	if err != nil {
		return err
	}
	if authFrame.Protocol != protocol.PPPPAP {
		return errors.New("sstp: client did not use negotiated PAP authentication")
	}
	id, username, password, err := protocol.DecodePAPRequest(authFrame.Payload)
	if err != nil {
		return err
	}
	expected, exists := users[username]
	if !exists || expected != password {
		_ = framer.WriteData(protocol.EncodePPP(protocol.PPPPAP, protocol.EncodePAPResult(false, id, "authentication failed")))
		return errors.New("sstp: invalid username or password")
	}
	if err := framer.WriteData(protocol.EncodePPP(protocol.PPPPAP, protocol.EncodePAPResult(true, id, "ok"))); err != nil {
		return err
	}
	connected, err := framer.ReadPacket()
	if err != nil {
		return err
	}
	binding, ok := protocol.AttributeValue(connected, protocol.AttrCryptoBinding)
	if !connected.Control || connected.Message != protocol.CallConnected || !ok {
		return errors.New("sstp: invalid CALL_CONNECTED")
	}
	if err := protocol.VerifyCryptoBinding(binding, nonce, certificateDER, nil); err != nil {
		return err
	}
	return negotiateServerIPCP(framer, assigned.Prev(), assigned)
}
