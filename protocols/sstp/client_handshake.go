package sstp

import (
	"errors"
	"net/netip"

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

	if err := negotiateClientLCP(framer, logf); err != nil {
		return netip.Addr{}, err
	}
	logf("PPP LCP negotiation completed: authentication=PAP")

	pap, err := protocol.EncodePAPRequest(2, username, password)
	if err != nil {
		return netip.Addr{}, err
	}
	if err := framer.WriteData(protocol.EncodePPP(protocol.PPPPAP, pap)); err != nil {
		return netip.Addr{}, err
	}
	logf("PPP PAP authentication request sent")
	result, err := readPPP(framer)
	if err != nil {
		return netip.Addr{}, err
	}
	if _, err := protocol.ExpectControl(result, protocol.PPPPAP, 2); err != nil {
		return netip.Addr{}, errors.New("sstp: PAP authentication rejected")
	}
	logf("PPP PAP authentication accepted")

	binding, err := protocol.CryptoBinding(hashProtocol, bindingRequest[4:], certificateDER, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	if err := framer.WriteControl(protocol.CallConnected, protocol.Attribute{ID: protocol.AttrCryptoBinding, Value: binding}); err != nil {
		return netip.Addr{}, err
	}
	logf("CALL_CONNECTED sent")
	return negotiateClientIPCP(framer, logf)
}
