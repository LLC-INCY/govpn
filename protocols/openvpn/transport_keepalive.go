package openvpn

import (
	"fmt"
	"time"
)

func (t *transport) keepaliveLoop(errCh chan<- error) {
	var pingTimer *time.Timer
	var pingTimerC <-chan time.Time
	if t.pingInterval > 0 {
		pingTimer = time.NewTimer(t.pingInterval)
		pingTimerC = pingTimer.C
		defer pingTimer.Stop()
	}
	var timeoutTicker *time.Ticker
	var timeoutTickerC <-chan time.Time
	if t.pingTimeout > 0 {
		checkInterval := t.pingTimeout / 4
		if checkInterval < time.Second {
			checkInterval = time.Second
		}
		timeoutTicker = time.NewTicker(checkInterval)
		timeoutTickerC = timeoutTicker.C
		defer timeoutTicker.Stop()
	}
	for {
		select {
		case <-t.sendActivity:
			if pingTimer != nil {
				resetTimer(pingTimer, t.pingInterval)
			}
		case <-pingTimerC:
			if err := t.sendPacket(openVPNPing); err != nil {
				errCh <- err
				return
			}
			t.pingSentLog.Do(func() { t.logf("keepalive send confirmed") })
			resetTimer(pingTimer, t.pingInterval)
		case now := <-timeoutTickerC:
			lastReceive := time.Unix(0, t.lastReceive.Load())
			if now.Sub(lastReceive) >= t.pingTimeout {
				errCh <- fmt.Errorf("openvpn: keepalive receive timeout after %s", t.pingTimeout)
				return
			}
		case <-t.endpoint.Closed():
			return
		}
	}
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(duration)
}
