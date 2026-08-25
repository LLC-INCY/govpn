package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type ICMPConn struct {
	deadline icmpDeadline
	ep       tcpip.Endpoint
	wq       *waiter.Queue
	packetEP tcpip.Endpoint
	packetWQ *waiter.Queue
	network  string
	remote   net.IP
	close    sync.Once
}

type icmpDeadline struct {
	mu          sync.Mutex
	readTimer   *time.Timer
	readCancel  chan struct{}
	writeTimer  *time.Timer
	writeCancel chan struct{}
}

func (d *icmpDeadline) init() {
	d.readCancel = make(chan struct{})
	d.writeCancel = make(chan struct{})
}

func (d *icmpDeadline) set(cancel *chan struct{}, timer **time.Timer, when time.Time) {
	if *timer != nil && !(*timer).Stop() {
		*cancel = make(chan struct{})
	}
	select {
	case <-*cancel:
		*cancel = make(chan struct{})
	default:
	}
	if when.IsZero() {
		*timer = nil
		return
	}
	delay := time.Until(when)
	if delay <= 0 {
		close(*cancel)
		*timer = nil
		return
	}
	c := *cancel
	*timer = time.AfterFunc(delay, func() { close(c) })
}

func (d *icmpDeadline) readChannel() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.readCancel
}

func (d *icmpDeadline) writeChannel() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.writeCancel
}

func (d *icmpDeadline) setRead(when time.Time) {
	d.mu.Lock()
	d.set(&d.readCancel, &d.readTimer, when)
	d.mu.Unlock()
}

func (d *icmpDeadline) setWrite(when time.Time) {
	d.mu.Lock()
	d.set(&d.writeCancel, &d.writeTimer, when)
	d.mu.Unlock()
}

func (d *icmpDeadline) SetDeadline(when time.Time) {
	d.mu.Lock()
	d.set(&d.readCancel, &d.readTimer, when)
	d.set(&d.writeCancel, &d.writeTimer, when)
	d.mu.Unlock()
}

func (s *Stack) DialICMPContext(ctx context.Context, network, address string) (*ICMPConn, error) {
	if ctx == nil {
		return nil, errors.New("govpn: nil ICMP context")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	transport, networkProto, normalized, err := icmpProtocol(network)
	if err != nil {
		return nil, err
	}
	remote, err := resolveICMPAddress(ctx, normalized, address)
	if err != nil {
		return nil, err
	}
	if !remote.IsValid() {
		return nil, errors.New("govpn: ICMP dial requires a destination address")
	}
	var wq waiter.Queue
	ep, tcpErr := s.stack.NewRawEndpoint(transport, networkProto, &wq, true)
	if tcpErr != nil {
		return nil, errors.New(tcpErr.String())
	}
	packetWQ := new(waiter.Queue)
	packetEP, tcpErr := s.stack.NewPacketEndpoint(true, networkProto, packetWQ)
	if tcpErr != nil {
		ep.Close()
		return nil, errors.New(tcpErr.String())
	}
	c := &ICMPConn{ep: ep, wq: &wq, packetEP: packetEP, packetWQ: packetWQ, network: normalized, remote: net.IP(remote.AsSlice())}
	c.deadline.init()
	return c, nil
}

func (s *Stack) ListenICMP(network, address string) (*ICMPConn, error) {
	transport, networkProto, normalized, err := icmpProtocol(network)
	if err != nil {
		return nil, err
	}
	local, err := resolveICMPAddress(context.Background(), normalized, address)
	if err != nil {
		return nil, err
	}
	var wq waiter.Queue
	ep, tcpErr := s.stack.NewRawEndpoint(transport, networkProto, &wq, true)
	if tcpErr != nil {
		return nil, errors.New(tcpErr.String())
	}
	if local.IsValid() {
		if tcpErr := ep.Bind(tcpip.FullAddress{NIC: nicID, Addr: tcpipAddr(local)}); tcpErr != nil {
			ep.Close()
			return nil, errors.New(tcpErr.String())
		}
	}
	packetWQ := new(waiter.Queue)
	packetEP, tcpErr := s.stack.NewPacketEndpoint(true, networkProto, packetWQ)
	if tcpErr != nil {
		ep.Close()
		return nil, errors.New(tcpErr.String())
	}
	c := &ICMPConn{ep: ep, wq: &wq, packetEP: packetEP, packetWQ: packetWQ, network: normalized}
	c.deadline.init()
	return c, nil
}

func icmpProtocol(network string) (tcpip.TransportProtocolNumber, tcpip.NetworkProtocolNumber, string, error) {
	network = strings.ToLower(network)
	switch network {
	case "icmp4", "icmpv4":
		return icmp.ProtocolNumber4, ipv4.ProtocolNumber, "icmp4", nil
	case "icmp6", "icmpv6":
		return icmp.ProtocolNumber6, ipv6.ProtocolNumber, "icmp6", nil
	default:
		return 0, 0, "", net.UnknownNetworkError(network)
	}
}

func resolveICMPAddress(ctx context.Context, network, address string) (netip.Addr, error) {
	if address == "" {
		return netip.Addr{}, nil
	}
	if addr, err := netip.ParseAddr(address); err == nil {
		if network == "icmp4" && !addr.Is4() {
			return netip.Addr{}, errors.New("govpn: ICMPv4 requires an IPv4 address")
		}
		if network == "icmp6" && !addr.Is6() {
			return netip.Addr{}, errors.New("govpn: ICMPv6 requires an IPv6 address")
		}
		return addr.Unmap(), nil
	}
	return resolveAddr(ctx, network, address)
}

func tcpipAddr(addr netip.Addr) tcpip.Address {
	if addr.Is4() {
		return tcpip.AddrFrom4(addr.As4())
	}
	return tcpip.AddrFrom16(addr.As16())
}

func (c *ICMPConn) newOpError(op string, err error) *net.OpError {
	return &net.OpError{Op: op, Net: c.network, Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: err}
}

func (c *ICMPConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *ICMPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	deadline := c.deadline.readChannel()
	select {
	case <-deadline:
		return 0, nil, c.newOpError("read", icmpTimeoutError{})
	default:
	}
	for {
		if n, address, done, err := c.readTransportPacket(b); done {
			if err != nil {
				return 0, nil, err
			}
			return n, &net.IPAddr{IP: net.IP(address.AsSlice())}, nil
		}
		if n, address, done, err := c.readPacketSocket(b); done {
			if err != nil {
				return 0, nil, err
			}
			return n, &net.IPAddr{IP: net.IP(address.AsSlice())}, nil
		}

		rawEntry, rawNotify := waiter.NewChannelEntry(waiter.ReadableEvents)
		packetEntry, packetNotify := waiter.NewChannelEntry(waiter.ReadableEvents)
		c.wq.EventRegister(&rawEntry)
		c.packetWQ.EventRegister(&packetEntry)
		select {
		case <-deadline:
			c.wq.EventUnregister(&rawEntry)
			c.packetWQ.EventUnregister(&packetEntry)
			return 0, nil, c.newOpError("read", icmpTimeoutError{})
		case <-rawNotify:
		case <-packetNotify:
		}
		c.wq.EventUnregister(&rawEntry)
		c.packetWQ.EventUnregister(&packetEntry)
	}
}

func (c *ICMPConn) readTransportPacket(b []byte) (int, netip.Addr, bool, error) {
	readBuffer := b
	if c.network == "icmp4" {
		readBuffer = make([]byte, len(b)+60)
	}
	w := tcpip.SliceWriter(readBuffer)
	result, tcpErr := c.ep.Read(&w, tcpip.ReadOptions{NeedRemoteAddr: true})
	if _, ok := tcpErr.(*tcpip.ErrWouldBlock); ok {
		return 0, netip.Addr{}, false, nil
	}
	if _, ok := tcpErr.(*tcpip.ErrClosedForReceive); ok {
		return 0, netip.Addr{}, true, io.EOF
	}
	if tcpErr != nil {
		return 0, netip.Addr{}, true, c.newOpError("read", errors.New(tcpErr.String()))
	}
	address, ok := netip.AddrFromSlice(result.RemoteAddr.Addr.AsSlice())
	if !ok {
		return 0, netip.Addr{}, true, errors.New("govpn: invalid ICMP source address")
	}
	count := result.Count
	if c.network == "icmp4" {
		headerLength, err := ipv4HeaderLength(readBuffer[:count])
		if err != nil {
			return 0, netip.Addr{}, true, c.newOpError("read", err)
		}
		count -= headerLength
		if !icmpChecksumValid(readBuffer[headerLength : headerLength+count]) {
			return 0, netip.Addr{}, false, nil
		}
		if count > len(b) {
			copy(b, readBuffer[headerLength:headerLength+len(b)])
			return len(b), address, true, io.ErrShortBuffer
		}
		copy(b, readBuffer[headerLength:headerLength+count])
	}
	return count, address.Unmap(), true, nil
}

func (c *ICMPConn) readPacketSocket(b []byte) (int, netip.Addr, bool, error) {
	packet := make([]byte, len(b)+60)
	w := tcpip.SliceWriter(packet)
	result, tcpErr := c.packetEP.Read(&w, tcpip.ReadOptions{})
	if _, ok := tcpErr.(*tcpip.ErrWouldBlock); ok {
		return 0, netip.Addr{}, false, nil
	}
	if _, ok := tcpErr.(*tcpip.ErrClosedForReceive); ok {
		return 0, netip.Addr{}, true, io.EOF
	}
	if tcpErr != nil {
		return 0, netip.Addr{}, true, c.newOpError("read", errors.New(tcpErr.String()))
	}
	payload, source, ok := parseICMPPacket(c.network, packet[:result.Count])
	if !ok {
		return 0, netip.Addr{}, false, nil
	}
	if len(payload) > len(b) {
		copy(b, payload[:len(b)])
		return len(b), source, true, io.ErrShortBuffer
	}
	copy(b, payload)
	return len(payload), source, true, nil
}

func parseICMPPacket(network string, packet []byte) ([]byte, netip.Addr, bool) {
	var payload []byte
	var source netip.Addr
	switch network {
	case "icmp4":
		headerLength, err := ipv4HeaderLength(packet)
		if err != nil || len(packet) < headerLength+8 || packet[9] != byte(icmp.ProtocolNumber4) {
			return nil, netip.Addr{}, false
		}
		var ok bool
		source, ok = netip.AddrFromSlice(packet[12:16])
		if !ok {
			return nil, netip.Addr{}, false
		}
		payload = packet[headerLength:]
		if !icmpChecksumValid(payload) || payload[0] == 0 || payload[0] == 8 {
			return nil, netip.Addr{}, false
		}
	case "icmp6":
		if len(packet) < 48 || packet[6] != byte(icmp.ProtocolNumber6) {
			return nil, netip.Addr{}, false
		}
		var ok bool
		source, ok = netip.AddrFromSlice(packet[8:24])
		if !ok {
			return nil, netip.Addr{}, false
		}
		payload = packet[40:]
		if !icmpv6ChecksumValid(source, packet[24:40], payload) || payload[0] == 128 || payload[0] == 129 {
			return nil, netip.Addr{}, false
		}
	default:
		return nil, netip.Addr{}, false
	}
	return payload, source.Unmap(), true
}

func icmpChecksumValid(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	return checksumSum(payload) == 0xffff
}

func icmpv6ChecksumValid(source netip.Addr, destination []byte, payload []byte) bool {
	if len(payload) < 4 || len(destination) != 16 {
		return false
	}
	var pseudo []byte
	sourceBytes := source.As16()
	pseudo = append(pseudo, sourceBytes[:]...)
	pseudo = append(pseudo, destination...)
	length := make([]byte, 8)
	binary.BigEndian.PutUint32(length[4:], uint32(len(payload)))
	pseudo = append(pseudo, length...)
	pseudo = append(pseudo, 0, 0, 0, byte(icmp.ProtocolNumber6))
	pseudo = append(pseudo, payload...)
	return checksumSum(pseudo) == 0xffff
}

func checksumSum(packet []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(packet); i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	if len(packet)&1 != 0 {
		sum += uint32(packet[len(packet)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return sum
}

func ipv4HeaderLength(packet []byte) (int, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, errors.New("govpn: malformed IPv4 packet")
	}
	length := int(packet[0]&0x0f) * 4
	if length < 20 || length > len(packet) {
		return 0, errors.New("govpn: malformed IPv4 header")
	}
	return length, nil
}

func (c *ICMPConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, nil)
}

func (c *ICMPConn) WriteTo(b []byte, address net.Addr) (int, error) {
	deadline := c.deadline.writeChannel()
	select {
	case <-deadline:
		return 0, c.newOpError("write", icmpTimeoutError{})
	default:
	}
	options := tcpip.WriteOptions{}
	if address != nil {
		ip, err := icmpAddrIP(address)
		if err != nil {
			return 0, c.newOpError("write", err)
		}
		options.To = &tcpip.FullAddress{NIC: nicID, Addr: tcpipAddr(ip)}
	} else if c.remote != nil {
		ip, ok := netip.AddrFromSlice(c.remote)
		if !ok {
			return 0, c.newOpError("write", errors.New("govpn: invalid ICMP destination"))
		}
		options.To = &tcpip.FullAddress{NIC: nicID, Addr: tcpipAddr(ip)}
	}
	if c.network == "icmp4" {
		b = icmpv4ChecksumPayload(b)
	}
	reader := bytes.NewReader(b)
	n, tcpErr := c.ep.Write(reader, options)
	if _, ok := tcpErr.(*tcpip.ErrWouldBlock); ok {
		entry, notify := waiter.NewChannelEntry(waiter.WritableEvents)
		c.wq.EventRegister(&entry)
		defer c.wq.EventUnregister(&entry)
		for {
			select {
			case <-deadline:
				return int(n), c.newOpError("write", icmpTimeoutError{})
			case <-notify:
			}
			n, tcpErr = c.ep.Write(reader, options)
			if _, ok := tcpErr.(*tcpip.ErrWouldBlock); !ok {
				break
			}
		}
	}
	if tcpErr != nil {
		return int(n), c.newOpError("write", errors.New(tcpErr.String()))
	}
	return int(n), nil
}

func icmpv4ChecksumPayload(payload []byte) []byte {
	if len(payload) < 4 {
		return payload
	}
	copyPayload := append([]byte(nil), payload...)
	copyPayload[2] = 0
	copyPayload[3] = 0
	var sum uint32
	for i := 0; i+1 < len(copyPayload); i += 2 {
		sum += uint32(copyPayload[i])<<8 | uint32(copyPayload[i+1])
	}
	if len(copyPayload)&1 != 0 {
		sum += uint32(copyPayload[len(copyPayload)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	checksum := ^uint16(sum)
	copyPayload[2] = byte(checksum >> 8)
	copyPayload[3] = byte(checksum)
	return copyPayload
}

func icmpAddrIP(address net.Addr) (netip.Addr, error) {
	var ip net.IP
	switch value := address.(type) {
	case *net.IPAddr:
		ip = value.IP
	case *net.UDPAddr:
		ip = value.IP
	case *net.TCPAddr:
		ip = value.IP
	default:
		return netip.Addr{}, errors.New("govpn: ICMP address must contain an IP")
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, errors.New("govpn: invalid ICMP address")
	}
	return addr.Unmap(), nil
}

func (c *ICMPConn) Close() error {
	c.close.Do(func() {
		c.ep.Close()
		c.packetEP.Close()
	})
	return nil
}

func (c *ICMPConn) LocalAddr() net.Addr {
	address, err := c.ep.GetLocalAddress()
	if err != nil {
		return nil
	}
	return &net.IPAddr{IP: net.IP(address.Addr.AsSlice())}
}

func (c *ICMPConn) RemoteAddr() net.Addr {
	if c.remote == nil {
		return nil
	}
	return &net.IPAddr{IP: append(net.IP(nil), c.remote...)}
}

func (c *ICMPConn) SetDeadline(when time.Time) error {
	c.deadline.SetDeadline(when)
	return nil
}

func (c *ICMPConn) SetReadDeadline(when time.Time) error {
	c.deadline.setRead(when)
	return nil
}

func (c *ICMPConn) SetWriteDeadline(when time.Time) error {
	c.deadline.setWrite(when)
	return nil
}

func (c *ICMPConn) SetTTL(ttl int) error {
	if c.network != "icmp4" {
		return errors.New("govpn: SetTTL is only valid for ICMPv4")
	}
	if err := c.ep.SetSockOptInt(tcpip.IPv4TTLOption, ttl); err != nil {
		return errors.New(err.String())
	}
	return nil
}

func (c *ICMPConn) SetHopLimit(limit int) error {
	if c.network != "icmp6" {
		return errors.New("govpn: SetHopLimit is only valid for ICMPv6")
	}
	if err := c.ep.SetSockOptInt(tcpip.IPv6HopLimitOption, limit); err != nil {
		return errors.New(err.String())
	}
	return nil
}

type icmpTimeoutError struct{}

func (icmpTimeoutError) Error() string   { return "i/o timeout" }
func (icmpTimeoutError) Timeout() bool   { return true }
func (icmpTimeoutError) Temporary() bool { return true }

var _ net.PacketConn = (*ICMPConn)(nil)
