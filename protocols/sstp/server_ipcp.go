package sstp

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"

	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

func negotiateServerIPCP(framer *protocol.Framer, gateway, assigned netip.Addr) error {
	const requestID = 2
	serverOptions := protocol.IPv4Option(gateway)
	if err := writePPPControl(framer, protocol.PPPIPCP, protocol.ConfigureRequest, requestID, serverOptions); err != nil {
		return err
	}
	clientConfigured, serverConfigured := false, false
	for attempts := 0; attempts < 32 && (!clientConfigured || !serverConfigured); attempts++ {
		frame, err := readPPP(framer)
		if err != nil {
			return err
		}
		if frame.Protocol != protocol.PPPIPCP {
			return fmt.Errorf("sstp: got PPP protocol %#x during IPCP negotiation", frame.Protocol)
		}
		control, err := protocol.DecodeControl(frame.Payload)
		if err != nil {
			return err
		}
		switch control.Code {
		case protocol.ConfigureRequest:
			requested, ok := protocol.ParseIPv4Option(control.Payload)
			if !ok {
				return errors.New("sstp: client IPCP request has no IPv4 address")
			}
			if requested != assigned {
				if err := writePPPControl(framer, protocol.PPPIPCP, protocol.ConfigureNak, control.ID, protocol.IPv4Option(assigned)); err != nil {
					return err
				}
				continue
			}
			if err := writePPPControl(framer, protocol.PPPIPCP, protocol.ConfigureAck, control.ID, control.Payload); err != nil {
				return err
			}
			clientConfigured = true
		case protocol.ConfigureAck:
			if control.ID == requestID && bytes.Equal(control.Payload, serverOptions) {
				serverConfigured = true
			}
		case protocol.ConfigureNak, protocol.ConfigureReject:
			return fmt.Errorf("sstp: client rejected server IPCP options with code %d", control.Code)
		default:
			return fmt.Errorf("sstp: unexpected IPCP code %d during negotiation", control.Code)
		}
	}
	if !clientConfigured || !serverConfigured {
		return errors.New("sstp: IPCP negotiation did not converge")
	}
	return nil
}
