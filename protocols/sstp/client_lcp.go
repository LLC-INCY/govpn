package sstp

import (
	"bytes"
	"errors"
	"fmt"

	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

// authMethod is what the server chose during LCP, and therefore which
// authentication exchange the handshake must run next.
type authMethod int

const (
	authPAP authMethod = iota
	authMSCHAPv2
)

func (a authMethod) String() string {
	if a == authMSCHAPv2 {
		return "MS-CHAPv2"
	}
	return "PAP"
}

func negotiateClientLCP(framer *protocol.Framer, logf func(string, ...any)) (authMethod, error) {
	const requestID = 1
	selected := authPAP
	clientOptions := []byte{protocol.LCPOptionMRU, 4, 0x05, 0xdc}
	if err := writePPPControl(framer, protocol.PPPLCP, protocol.ConfigureRequest, requestID, clientOptions); err != nil {
		return selected, err
	}
	logf("PPP LCP client Configure-Request sent")
	clientConfigured, serverConfigured := false, false
	for attempts := 0; attempts < 16 && (!clientConfigured || !serverConfigured); attempts++ {
		frame, err := readPPP(framer)
		if err != nil {
			return selected, err
		}
		if frame.Protocol != protocol.PPPLCP {
			return selected, fmt.Errorf("sstp: got PPP protocol %#x during LCP negotiation", frame.Protocol)
		}
		control, err := protocol.DecodeControl(frame.Payload)
		if err != nil {
			return selected, err
		}
		switch control.Code {
		case protocol.ConfigureRequest:
			authentication, algorithm, found, err := protocol.ParseLCPAuthentication(control.Payload)
			if err != nil {
				return selected, err
			}
			switch {
			case !found, authentication == protocol.PPPPAP:
				// No authentication option, or PAP: nothing to negotiate.
			case authentication == protocol.PPPCHAP &&
				len(algorithm) == 1 && algorithm[0] == protocol.CHAPAlgorithmMSCHAPv2:
				// MS-CHAPv2 is what Windows RRAS and MikroTik ask for by
				// default, and unlike PAP it does not put the password on
				// the wire, so accept it as offered.
				selected = authMSCHAPv2
			default:
				// Anything else (EAP, plain CHAP-MD5) is not implemented.
				// Nak with MS-CHAPv2 rather than PAP: it is the stronger of
				// the two we can actually do.
				logf("PPP LCP server requested authentication=%s; requesting MS-CHAPv2", lcpAuthenticationName(authentication, algorithm))
				if err := writePPPControl(framer, protocol.PPPLCP, protocol.ConfigureNak, control.ID, protocol.MSCHAPv2AuthenticationOption()); err != nil {
					return selected, err
				}
				continue
			}
			if err := writePPPControl(framer, protocol.PPPLCP, protocol.ConfigureAck, control.ID, control.Payload); err != nil {
				return selected, err
			}
			logf("PPP LCP server Configure-Request acknowledged: id=%d", control.ID)
			serverConfigured = true
		case protocol.ConfigureAck:
			if control.ID == requestID && bytes.Equal(control.Payload, clientOptions) {
				clientConfigured = true
				logf("PPP LCP client Configure-Request acknowledged")
			}
		case protocol.ConfigureNak, protocol.ConfigureReject:
			return selected, fmt.Errorf("sstp: server rejected client LCP options with code %d", control.Code)
		default:
			return selected, fmt.Errorf("sstp: unexpected LCP code %d during negotiation", control.Code)
		}
	}
	if !clientConfigured || !serverConfigured {
		return selected, errors.New("sstp: LCP negotiation did not converge")
	}
	return selected, nil
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
