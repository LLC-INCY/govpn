package sstp

import (
	"bytes"
	"errors"
	"fmt"

	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

func negotiateServerLCP(framer *protocol.Framer) error {
	const requestID = 1
	lcpOptions := append([]byte{protocol.LCPOptionMRU, 4, 0x05, 0xdc}, protocol.PAPAuthenticationOption()...)
	if err := writePPPControl(framer, protocol.PPPLCP, protocol.ConfigureRequest, requestID, lcpOptions); err != nil {
		return err
	}
	clientConfigured, serverConfigured := false, false
	for attempts := 0; attempts < 16 && (!clientConfigured || !serverConfigured); attempts++ {
		frame, err := readPPP(framer)
		if err != nil {
			return err
		}
		if frame.Protocol != protocol.PPPLCP {
			return fmt.Errorf("sstp: got PPP protocol %#x during LCP negotiation", frame.Protocol)
		}
		control, err := protocol.DecodeControl(frame.Payload)
		if err != nil {
			return err
		}
		switch control.Code {
		case protocol.ConfigureRequest:
			if err := writePPPControl(framer, protocol.PPPLCP, protocol.ConfigureAck, control.ID, control.Payload); err != nil {
				return err
			}
			clientConfigured = true
		case protocol.ConfigureAck:
			if control.ID == requestID && bytes.Equal(control.Payload, lcpOptions) {
				serverConfigured = true
			}
		case protocol.ConfigureNak, protocol.ConfigureReject:
			return fmt.Errorf("sstp: client rejected server LCP options with code %d", control.Code)
		default:
			return fmt.Errorf("sstp: unexpected LCP code %d during negotiation", control.Code)
		}
	}
	if !clientConfigured || !serverConfigured {
		return errors.New("sstp: LCP negotiation did not converge")
	}
	return nil
}
