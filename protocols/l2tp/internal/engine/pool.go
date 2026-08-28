package engine

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

var errAddressPoolExhausted = errors.New("l2tp: address pool exhausted")

// addressPool allocates IPv4 hosts after the gateway and before the broadcast
// address. The server owns the first usable host; clients start at the second.
type addressPool struct {
	mu          sync.Mutex
	first, last uint32
	used        map[uint32]struct{}
}

func newAddressPool(network *net.IPNet, gateway net.IP) *addressPool {
	n := binary.BigEndian.Uint32(network.IP.To4())
	mask := binary.BigEndian.Uint32(network.Mask)
	broadcast := n | ^mask
	first := binary.BigEndian.Uint32(gateway.To4()) + 1
	return &addressPool{first: first, last: broadcast - 1, used: make(map[uint32]struct{})}
}

func (p *addressPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.first > p.last {
		return nil, errAddressPoolExhausted
	}
	for candidate := p.first; ; candidate++ {
		if _, exists := p.used[candidate]; exists {
			if candidate == p.last {
				break
			}
			continue
		}
		p.used[candidate] = struct{}{}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], candidate)
		return net.IPv4(b[0], b[1], b[2], b[3]), nil
	}
	return nil, errAddressPoolExhausted
}

func (p *addressPool) Release(ip net.IP) {
	v4 := ip.To4()
	if v4 == nil {
		return
	}
	p.mu.Lock()
	delete(p.used, binary.BigEndian.Uint32(v4))
	p.mu.Unlock()
}
