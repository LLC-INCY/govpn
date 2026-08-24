package openvpn

import (
	"errors"
	"time"
)

func (e *endpoint) retransmitLoop() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			var resend [][]byte
			exhausted := false
			e.pendingMu.Lock()
			for _, packet := range e.pending {
				if now.Sub(packet.lastSent) < time.Second {
					continue
				}
				if packet.attempts >= 6 {
					exhausted = true
					break
				}
				packet.attempts++
				packet.lastSent = now
				resend = append(resend, append([]byte(nil), packet.datagram...))
			}
			e.pendingMu.Unlock()
			if exhausted {
				e.fail(errors.New("openvpn: control packet acknowledgment timeout"))
				return
			}
			for _, datagram := range resend {
				e.writeMu.Lock()
				_, err := e.conn.Write(datagram)
				e.writeMu.Unlock()
				if err != nil {
					e.fail(err)
					return
				}
			}
		case <-e.closed:
			return
		}
	}
}
