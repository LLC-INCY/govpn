package netstack

import (
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (s *Stack) outboundLoop() {
	defer s.wg.Done()
	for {
		packet := s.link.ReadContext(s.ctx)
		if packet == nil {
			return
		}
		view := packet.ToView()
		payload := append([]byte(nil), view.AsSlice()...)
		view.Release()
		packet.DecRef()
		if err := s.device.Inject(s.ctx, payload); err != nil {
			return
		}
	}
}

func (s *Stack) inboundLoop() {
	defer s.wg.Done()
	for {
		packet, err := s.device.Receive(s.ctx)
		if err != nil {
			return
		}
		if len(packet) == 0 {
			continue
		}
		var protocol tcpip.NetworkProtocolNumber
		switch packet[0] >> 4 {
		case 4:
			protocol = ipv4.ProtocolNumber
		case 6:
			protocol = ipv6.ProtocolNumber
		default:
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		s.link.InjectInbound(protocol, pkt)
		pkt.DecRef()
	}
}
