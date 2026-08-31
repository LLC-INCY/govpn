package engine

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"github.com/bclswl0827/govpn/protocols/l2tp/internal/esp"
	"github.com/bclswl0827/govpn/protocols/l2tp/internal/ikev1"
	"github.com/bclswl0827/govpn/protocols/l2tp/internal/logutil"
	"github.com/bclswl0827/govpn/internal/mschap"
	"github.com/bclswl0827/govpn/protocols/l2tp/internal/ppp"
)

// ServerConfig configures an L2TP/IPsec responder engine.
type ServerConfig struct {
	PSK      []byte
	Users    map[string]string
	PublicIP net.IP
	Network  *net.IPNet
	Gateway  net.IP
	DNS      []net.IP
	IKEPort  int
	NATTPort int
	Logger   *logutil.Logger
}

// Server demultiplexes IKE by initiator cookie, ESP by inbound SPI, and inner
// packets by the client address assigned over IPCP.
type Server struct {
	cfg      ServerConfig
	ikeConn  *net.UDPConn
	nattConn *net.UDPConn
	tun      tunIO
	pool     *addressPool
	logger   *logutil.Logger

	mu       sync.Mutex
	byCookie map[[8]byte]*serverPeer
	bySPI    map[uint32]*serverPeer
	byIP     map[uint32]*serverPeer
	closed   bool

	closeOnce sync.Once
}

// NewServer builds a responder over bound IKE and NAT-T sockets.
func NewServer(ikeConn, nattConn *net.UDPConn, tun tunIO, cfg ServerConfig) *Server {
	return &Server{
		cfg: cfg, ikeConn: ikeConn, nattConn: nattConn, tun: tun,
		pool: newAddressPool(cfg.Network, cfg.Gateway), logger: cfg.Logger,
		byCookie: make(map[[8]byte]*serverPeer),
		bySPI:    make(map[uint32]*serverPeer), byIP: make(map[uint32]*serverPeer),
	}
}

// Serve runs until Close closes a socket.
func (s *Server) Serve() error {
	go s.tunLoop()
	go s.recvIKE()
	s.recvNATT()
	return nil
}

// Close stops the listeners and all active tunnels.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		peers := make([]*serverPeer, 0, len(s.byCookie))
		for _, p := range s.byCookie {
			peers = append(peers, p)
		}
		s.mu.Unlock()
		_ = s.ikeConn.Close()
		_ = s.nattConn.Close()
		for _, p := range peers {
			s.removePeer(p, nil)
		}
	})
	return nil
}

func (s *Server) recvIKE() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.ikeConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.dispatchIKE(append([]byte(nil), buf[:n]...), addr, false)
	}
}

func (s *Server) recvNATT() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.nattConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		if message, ok := isIKE(pkt); ok {
			s.dispatchIKE(message, addr, true)
			continue
		}
		if p := s.peerBySPI(pkt); p != nil {
			p.noteNATTAddr(addr)
			p.handleESP(pkt)
		}
	}
}

func (s *Server) dispatchIKE(message []byte, addr *net.UDPAddr, natt bool) {
	cookie, ok := ikev1.InitiatorCookie(message)
	if !ok {
		return
	}
	p := s.peerFor(cookie, addr)
	if p == nil {
		return
	}
	p.noteIKEAddr(addr, natt)
	p.ike.HandleInbound(message)
}

func (s *Server) peerFor(cookie [8]byte, addr *net.UDPAddr) *serverPeer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.byCookie[cookie]; p != nil {
		return p
	}
	if s.closed {
		return nil
	}
	ikePort := s.cfg.IKEPort
	if ikePort == 0 {
		ikePort = defaultIKEPort
	}
	peerNATTPort := s.cfg.NATTPort
	if peerNATTPort == 0 {
		peerNATTPort = nattPort
	}
	p := &serverPeer{
		srv: s, cookie: cookie, addr: cloneUDPAddr(addr),
		nattAddr: &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: peerNATTPort},
	}
	p.ike = ikev1.NewSession(ikev1.Config{
		Role: ikev1.Responder, PSK: s.cfg.PSK,
		LocalIP: s.cfg.PublicIP, PeerIP: addr.IP,
		LocalPort: uint16(ikePort), PeerPort: uint16(addr.Port),
		Send: p.sendIKE, Handler: p, Logger: s.logger,
	})
	s.byCookie[cookie] = p
	s.logger.Printf("l2tp: new peer %s (cookie %x)", addr, cookie)
	return p
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

func (s *Server) peerBySPI(pkt []byte) *serverPeer {
	if len(pkt) < 4 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bySPI[binary.BigEndian.Uint32(pkt[:4])]
}

func (s *Server) peerByIP(ip net.IP) *serverPeer {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byIP[binary.BigEndian.Uint32(v4)]
}

func (s *Server) removePeer(p *serverPeer, err error) {
	s.mu.Lock()
	if s.byCookie[p.cookie] != p {
		s.mu.Unlock()
		return
	}
	p.mu.Lock()
	p.closed = true
	p.networkUp = false
	inSPI := p.inSPI
	innerIP := append(net.IP(nil), p.innerIP...)
	tunnel := p.tunnel
	addr := cloneUDPAddr(p.addr)
	delete(s.byCookie, p.cookie)
	if inSPI != 0 {
		delete(s.bySPI, inSPI)
	}
	if v4 := innerIP.To4(); v4 != nil {
		delete(s.byIP, binary.BigEndian.Uint32(v4))
	}
	p.mu.Unlock()
	s.mu.Unlock()
	if innerIP != nil {
		s.pool.Release(innerIP)
	}
	if tunnel != nil {
		tunnel.Close()
	}
	s.logger.Printf("l2tp: peer %s gone: %v", addr, err)
}

func (s *Server) auth(username string) (string, bool) {
	password, ok := s.cfg.Users[username]
	return password, ok
}

func (s *Server) tunLoop() {
	buf := make([]byte, 65535)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			return
		}
		p := s.peerByIP(ipv4Dst(buf[:n]))
		if p == nil {
			continue
		}
		p.mu.Lock()
		tunnel, allowed := p.tunnel, p.networkUp && !p.closed
		p.mu.Unlock()
		if tunnel != nil && allowed {
			packet := append([]byte(nil), buf[:n]...)
			_ = tunnel.SendPPP(ppp.EncapsulateIP(packet))
		}
	}
}

type serverPeer struct {
	srv    *Server
	cookie [8]byte
	ike    *ikev1.Session

	mu        sync.Mutex
	addr      *net.UDPAddr
	nattAddr  *net.UDPAddr
	sa        *esp.SA
	inSPI     uint32
	tunnel    *Tunnel
	ppp       *ppp.ServerSession
	innerIP   net.IP
	networkUp bool
	closed    bool
}

func (p *serverPeer) noteIKEAddr(addr *net.UDPAddr, natt bool) {
	p.mu.Lock()
	if natt {
		p.nattAddr = cloneUDPAddr(addr)
	} else {
		p.addr = cloneUDPAddr(addr)
	}
	p.mu.Unlock()
}

func (p *serverPeer) noteNATTAddr(addr *net.UDPAddr) {
	p.mu.Lock()
	p.nattAddr = cloneUDPAddr(addr)
	p.mu.Unlock()
}

func (p *serverPeer) sendIKE(message []byte, natt bool) error {
	p.mu.Lock()
	ikeAddr, nattAddr := cloneUDPAddr(p.addr), cloneUDPAddr(p.nattAddr)
	p.mu.Unlock()
	if natt {
		_, err := p.srv.nattConn.WriteToUDP(markIKE(message), nattAddr)
		return err
	}
	_, err := p.srv.ikeConn.WriteToUDP(message, ikeAddr)
	return err
}

func (p *serverPeer) handleESP(pkt []byte) {
	p.mu.Lock()
	sa, tunnel, closed := p.sa, p.tunnel, p.closed
	p.mu.Unlock()
	if closed || sa == nil || tunnel == nil {
		return
	}
	inner, nextHeader, err := sa.Decapsulate(pkt)
	if err != nil || nextHeader != ipProtoUDP {
		return
	}
	if l2tp, ok := unwrapUDP(inner); ok {
		tunnel.HandleInbound(l2tp)
	}
}

func (p *serverPeer) Established(result ikev1.Result) {
	p.srv.mu.Lock()
	p.mu.Lock()
	if p.closed || p.srv.byCookie[p.cookie] != p {
		p.mu.Unlock()
		p.srv.mu.Unlock()
		return
	}
	p.sa = newESPSA(result)
	p.inSPI = result.InSPI
	p.tunnel = NewTunnel(RoleLNS, p.espSend, p)
	p.srv.bySPI[result.InSPI] = p
	addr := cloneUDPAddr(p.addr)
	p.mu.Unlock()
	p.srv.mu.Unlock()
	p.srv.logger.Printf("l2tp: IPsec SA established with %s", addr)
}

func (p *serverPeer) Failed(err error) { p.srv.removePeer(p, err) }

func (p *serverPeer) espSend(l2tp []byte) error {
	p.mu.Lock()
	sa, addr := p.sa, cloneUDPAddr(p.nattAddr)
	p.mu.Unlock()
	if sa == nil {
		return errors.New("l2tp: ESP SA not ready")
	}
	pkt, err := sa.Encapsulate(wrapUDP(l2tp), ipProtoUDP)
	if err != nil {
		return err
	}
	_, err = p.srv.nattConn.WriteToUDP(pkt, addr)
	return err
}

func (p *serverPeer) SessionUp() {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return
	}
	ip, err := p.srv.pool.Allocate()
	if err != nil {
		p.srv.removePeer(p, err)
		return
	}
	p.srv.mu.Lock()
	p.mu.Lock()
	if p.closed || p.srv.byCookie[p.cookie] != p {
		p.mu.Unlock()
		p.srv.mu.Unlock()
		p.srv.pool.Release(ip)
		return
	}
	p.innerIP = ip
	p.ppp = ppp.NewServer(ppp.ServerConfig{
		ClientIP: ip, ServerIP: p.srv.cfg.Gateway, DNS: p.srv.cfg.DNS, Auth: p.srv.auth,
	}, p.tunnel, serverPPP{p})
	serverPPP := p.ppp
	addr := cloneUDPAddr(p.addr)
	p.mu.Unlock()
	p.srv.mu.Unlock()
	p.srv.logger.Printf("l2tp: L2TP session up for %s, assigning %s", addr, ip)
	serverPPP.Start()
}

func (p *serverPeer) DataFrame(frame []byte) {
	if ip, ok := ppp.IsIP(frame); ok {
		p.mu.Lock()
		allowed := p.networkUp && ipv4Src(ip).Equal(p.innerIP)
		p.mu.Unlock()
		if allowed {
			_, _ = p.srv.tun.Write(ip)
		}
		return
	}
	p.mu.Lock()
	serverPPP, closed := p.ppp, p.closed
	p.mu.Unlock()
	if serverPPP != nil && !closed {
		serverPPP.Receive(frame)
	}
}

func (p *serverPeer) Closed(err error) { p.srv.removePeer(p, err) }

type serverPPP struct{ p *serverPeer }

func (h serverPPP) Authenticated(string, string, [mschap.NTResponseLen]byte) {}
func (h serverPPP) NetworkUp() {
	h.p.srv.mu.Lock()
	h.p.mu.Lock()
	if h.p.closed || h.p.srv.byCookie[h.p.cookie] != h.p {
		h.p.mu.Unlock()
		h.p.srv.mu.Unlock()
		return
	}
	h.p.networkUp = true
	if v4 := h.p.innerIP.To4(); v4 != nil {
		h.p.srv.byIP[binary.BigEndian.Uint32(v4)] = h.p
	}
	addr := cloneUDPAddr(h.p.addr)
	h.p.mu.Unlock()
	h.p.srv.mu.Unlock()
	h.p.srv.logger.Printf("l2tp: PPP up for %s", addr)
}
func (h serverPPP) Closed(err error) { h.p.srv.removePeer(h.p, err) }

func ipv4Src(packet []byte) net.IP {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(packet[12], packet[13], packet[14], packet[15])
}

func ipv4Dst(packet []byte) net.IP {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(packet[16], packet[17], packet[18], packet[19])
}
