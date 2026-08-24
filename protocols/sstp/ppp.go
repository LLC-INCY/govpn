package sstp

import (
	"fmt"

	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

func readPPP(framer *protocol.Framer) (protocol.PPPFrame, error) {
	for {
		packet, err := framer.ReadPacket()
		if err != nil {
			return protocol.PPPFrame{}, err
		}
		if packet.Control {
			switch packet.Message {
			case protocol.EchoRequest:
				if err := framer.WriteControl(protocol.EchoResponse); err != nil {
					return protocol.PPPFrame{}, err
				}
				continue
			case protocol.CallAbort:
				_ = framer.WriteControl(protocol.CallAbort)
				return protocol.PPPFrame{}, protocol.TerminationError(packet)
			case protocol.CallDisconnect:
				_ = framer.WriteControl(protocol.CallDisconnectAck)
				return protocol.PPPFrame{}, protocol.TerminationError(packet)
			default:
				return protocol.PPPFrame{}, fmt.Errorf("sstp: unexpected control message %d", packet.Message)
			}
		}
		return protocol.DecodePPP(packet.Payload)
	}
}

func writePPPControl(framer *protocol.Framer, pppProtocol uint16, code, id byte, payload []byte) error {
	return framer.WriteData(protocol.EncodePPP(pppProtocol, protocol.EncodeControl(code, id, payload)))
}
