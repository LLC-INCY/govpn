package sstp

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"

	protocol "github.com/bclswl0827/govpn/protocols/sstp/internal"
)

func negotiateClientIPCP(framer *protocol.Framer, logf func(string, ...any)) (netip.Addr, error) {
	requestID := byte(3)
	requested := netip.IPv4Unspecified()
	requestOptions := protocol.IPv4Option(requested)
	if err := writePPPControl(framer, protocol.PPPIPCP, protocol.ConfigureRequest, requestID, requestOptions); err != nil {
		return netip.Addr{}, err
	}
	logf("PPP IPCP client Configure-Request sent")

	clientConfigured, serverConfigured := false, false
	var assigned netip.Addr
	for attempts := 0; attempts < 32 && (!clientConfigured || !serverConfigured); attempts++ {
		frame, err := readPPP(framer)
		if err != nil {
			return netip.Addr{}, err
		}
		if frame.Protocol != protocol.PPPIPCP {
			return netip.Addr{}, fmt.Errorf("sstp: got PPP protocol %#x during IPCP negotiation", frame.Protocol)
		}
		control, err := protocol.DecodeControl(frame.Payload)
		if err != nil {
			return netip.Addr{}, err
		}
		switch control.Code {
		case protocol.ConfigureRequest:
			if err := writePPPControl(framer, protocol.PPPIPCP, protocol.ConfigureAck, control.ID, control.Payload); err != nil {
				return netip.Addr{}, err
			}
			serverConfigured = true
			logf("PPP IPCP server Configure-Request acknowledged: id=%d", control.ID)
		case protocol.ConfigureNak:
			if control.ID != requestID {
				continue
			}
			offered, ok := protocol.ParseIPv4Option(control.Payload)
			if !ok || offered.IsUnspecified() {
				return netip.Addr{}, errors.New("sstp: server did not offer an IPv4 address")
			}
			assigned = offered
			requested = offered
			requestID++
			requestOptions = protocol.IPv4Option(requested)
			if err := writePPPControl(framer, protocol.PPPIPCP, protocol.ConfigureRequest, requestID, requestOptions); err != nil {
				return netip.Addr{}, err
			}
			logf("PPP IPCP address offered: %s", assigned)
		case protocol.ConfigureAck:
			if control.ID == requestID && bytes.Equal(control.Payload, requestOptions) {
				if requested.IsUnspecified() {
					return netip.Addr{}, errors.New("sstp: server acknowledged an unspecified IPv4 address")
				}
				assigned = requested
				clientConfigured = true
				logf("PPP IPCP client Configure-Request acknowledged")
			}
		case protocol.ConfigureReject:
			return netip.Addr{}, errors.New("sstp: server rejected the IPv4 IPCP option")
		default:
			return netip.Addr{}, fmt.Errorf("sstp: unexpected IPCP code %d during negotiation", control.Code)
		}
	}
	if !clientConfigured || !serverConfigured || !assigned.IsValid() {
		return netip.Addr{}, errors.New("sstp: IPCP negotiation did not converge")
	}
	logf("PPP IPCP negotiation completed")
	return assigned, nil
}
