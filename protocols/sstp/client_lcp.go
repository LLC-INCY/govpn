package sstp

import (
	"bytes"
	"errors"
	"fmt"

	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

func negotiateClientLCP(framer *protocol.Framer, logf func(string, ...any)) error {
	const requestID = 1
	clientOptions := []byte{protocol.LCPOptionMRU, 4, 0x05, 0xdc}
	if err := writePPPControl(framer, protocol.PPPLCP, protocol.ConfigureRequest, requestID, clientOptions); err != nil {
		return err
	}
	logf("PPP LCP client Configure-Request sent")
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
			authentication, algorithm, found, err := protocol.ParseLCPAuthentication(control.Payload)
			if err != nil {
				return err
			}
			if found && authentication != protocol.PPPPAP {
				logf("PPP LCP server requested authentication=%s; requesting PAP", lcpAuthenticationName(authentication, algorithm))
				if err := writePPPControl(framer, protocol.PPPLCP, protocol.ConfigureNak, control.ID, protocol.PAPAuthenticationOption()); err != nil {
					return err
				}
				continue
			}
			if err := writePPPControl(framer, protocol.PPPLCP, protocol.ConfigureAck, control.ID, control.Payload); err != nil {
				return err
			}
			logf("PPP LCP server Configure-Request acknowledged: id=%d", control.ID)
			serverConfigured = true
		case protocol.ConfigureAck:
			if control.ID == requestID && bytes.Equal(control.Payload, clientOptions) {
				clientConfigured = true
				logf("PPP LCP client Configure-Request acknowledged")
			}
		case protocol.ConfigureNak, protocol.ConfigureReject:
			return fmt.Errorf("sstp: server rejected client LCP options with code %d", control.Code)
		default:
			return fmt.Errorf("sstp: unexpected LCP code %d during negotiation", control.Code)
		}
	}
	if !clientConfigured || !serverConfigured {
		return errors.New("sstp: LCP negotiation did not converge")
	}
	return nil
}

func lcpAuthenticationName(authentication uint16, algorithm []byte) string {
	switch authentication {
	case protocol.PPPPAP:
		return "PAP"
	case protocol.PPPCHAP:
		if len(algorithm) == 1 && algorithm[0] == protocol.CHAPAlgorithmMSCHAPv2 {
			return "MS-CHAPv2"
		}
		return fmt.Sprintf("CHAP(%x)", algorithm)
	case protocol.PPPEAP:
		return "EAP"
	default:
		return fmt.Sprintf("%#x", authentication)
	}
}
