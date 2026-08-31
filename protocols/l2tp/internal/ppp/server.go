package ppp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/bclswl0827/govpn/internal/mschap"
)

// Authenticator returns the password for a username, or ok=false when the user
// is unknown. MS-CHAPv2 requires the plaintext password to verify the response.
type Authenticator func(username string) (password string, ok bool)

// ServerHandler receives PPP authenticator lifecycle events.
type ServerHandler interface {
	Authenticated(username, password string, ntResponse [mschap.NTResponseLen]byte)
	NetworkUp()
	Closed(error)
}

// ServerConfig is the addressing and authentication a server assigns over PPP.
type ServerConfig struct {
	ClientIP net.IP
	ServerIP net.IP
	DNS      []net.IP
	Auth     Authenticator
}

// ServerSession is the authenticator side of a PPP link. It negotiates LCP,
// requires MS-CHAPv2, verifies the client, and assigns IPv4 settings with IPCP.
type ServerSession struct {
	cfg ServerConfig
	tr  Transport
	h   ServerHandler

	mu    sync.Mutex
	phase phase
	magic uint32
	reqID byte

	lcpReqID                    byte
	lcpConfigReq                []byte
	lcpLocalOpen, lcpRemoteOpen bool

	authChallenge [mschap.ChallengeLen]byte
	username      string
	password      string
	ntResponse    [mschap.NTResponseLen]byte

	ipcpReqID                     byte
	ipcpConfigReq                 []byte
	ipcpLocalOpen, ipcpRemoteOpen bool

	lcpRestart, ipcpRestart restartTimer
}

// NewServer builds a PPP authenticator session.
func NewServer(cfg ServerConfig, tr Transport, h ServerHandler) *ServerSession {
	var magic [4]byte
	_, _ = rand.Read(magic[:])
	return &ServerSession{cfg: cfg, tr: tr, h: h, magic: binary.BigEndian.Uint32(magic[:])}
}

// Start opens LCP and requests MS-CHAPv2 authentication.
func (s *ServerSession) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendLCPConfigReq()
}

// Receive processes one peer PPP frame.
func (s *ServerSession) Receive(frame []byte) {
	protocol, payload, ok := decodeFrame(frame)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == phaseClosed {
		return
	}
	switch protocol {
	case ProtocolLCP:
		s.handleLCP(payload)
	case ProtocolCHAP:
		s.handleCHAP(payload)
	case ProtocolIPCP:
		s.handleIPCP(payload)
	}
}

func (s *ServerSession) send(protocol uint16, payload []byte) {
	if err := s.tr.SendPPP(encodeFrame(protocol, payload)); err != nil {
		s.failLocked(fmt.Errorf("ppp: send: %w", err))
	}
}

func (s *ServerSession) nextID() byte { s.reqID++; return s.reqID }

func (s *ServerSession) failLocked(err error) {
	if s.phase == phaseClosed {
		return
	}
	s.phase = phaseClosed
	s.lcpRestart.stop()
	s.ipcpRestart.stop()
	s.h.Closed(err)
}

func (s *ServerSession) withLock(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != phaseClosed {
		fn()
	}
}

func (s *ServerSession) sendLCPConfigReq() {
	var magic [4]byte
	binary.BigEndian.PutUint32(magic[:], s.magic)
	opts := []option{
		{Type: optAuthProto, Value: authMSCHAPv2},
		{Type: optMagic, Value: magic[:]},
	}
	s.lcpReqID = s.nextID()
	s.lcpConfigReq = cpPacket{Code: codeConfigureRequest, ID: s.lcpReqID, Body: marshalOptions(opts)}.marshal()
	s.resendLCPConfigReq()
}

func (s *ServerSession) resendLCPConfigReq() {
	s.send(ProtocolLCP, s.lcpConfigReq)
	s.lcpRestart.arm(s.withLock, s.resendLCPConfigReq, func() {
		s.failLocked(fmt.Errorf("ppp: no reply to the LCP Configure-Request"))
	})
}

func (s *ServerSession) handleLCP(payload []byte) {
	pkt, ok := parseCP(payload)
	if !ok {
		return
	}
	s.lcpRestart.alive()
	switch pkt.Code {
	case codeConfigureRequest:
		s.handleLCPConfigReq(pkt)
	case codeConfigureAck:
		if pkt.ID == s.lcpReqID {
			s.lcpRestart.stop()
			s.lcpLocalOpen = true
			s.maybeLCPUp()
		}
	case codeConfigureNak, codeConfigureReject:
		s.failLocked(fmt.Errorf("ppp: client rejected MS-CHAPv2 authentication"))
	case codeTerminateRequest:
		s.send(ProtocolLCP, cpPacket{Code: codeTerminateAck, ID: pkt.ID}.marshal())
		s.failLocked(fmt.Errorf("ppp: client closed the link"))
	case codeEchoRequest:
		s.sendEchoReply(pkt)
	}
}

func (s *ServerSession) handleLCPConfigReq(pkt cpPacket) {
	opts, ok := parseOptions(pkt.Body)
	if !ok {
		return
	}
	var rejected []option
	for _, o := range opts {
		switch o.Type {
		case optMRU, optMagic, optQuality, optPFC, optACFC:
		default:
			rejected = append(rejected, o)
		}
	}
	if len(rejected) > 0 {
		s.send(ProtocolLCP, cpPacket{Code: codeConfigureReject, ID: pkt.ID, Body: marshalOptions(rejected)}.marshal())
		return
	}
	s.send(ProtocolLCP, cpPacket{Code: codeConfigureAck, ID: pkt.ID, Body: pkt.Body}.marshal())
	s.lcpRemoteOpen = true
	s.maybeLCPUp()
}

func (s *ServerSession) sendEchoReply(req cpPacket) {
	var magic [4]byte
	binary.BigEndian.PutUint32(magic[:], s.magic)
	body := magic[:]
	if len(req.Body) >= 4 {
		body = append(magic[:], req.Body[4:]...)
	}
	s.send(ProtocolLCP, cpPacket{Code: codeEchoReply, ID: req.ID, Body: body}.marshal())
}

func (s *ServerSession) maybeLCPUp() {
	if s.phase != phaseLCP || !s.lcpLocalOpen || !s.lcpRemoteOpen {
		return
	}
	s.phase = phaseAuth
	s.sendChallenge()
}

func (s *ServerSession) sendChallenge() {
	if _, err := rand.Read(s.authChallenge[:]); err != nil {
		s.failLocked(fmt.Errorf("ppp: challenge: %w", err))
		return
	}
	s.send(ProtocolCHAP, cpPacket{Code: chapChallenge, ID: s.nextID(), Body: buildChallenge(s.authChallenge, "govpn")}.marshal())
}

func (s *ServerSession) handleCHAP(payload []byte) {
	pkt, ok := parseCP(payload)
	if !ok || pkt.Code != chapResponse {
		return
	}
	peerChallenge, ntResponse, username, ok := parseResponse(pkt.Body)
	if !ok {
		s.failLocked(fmt.Errorf("ppp: malformed MS-CHAPv2 response"))
		return
	}
	password, known := "", false
	if s.cfg.Auth != nil {
		password, known = s.cfg.Auth(username)
	}
	if !known || !verifyResponse(s.authChallenge, peerChallenge, username, password, ntResponse) {
		s.send(ProtocolCHAP, cpPacket{Code: chapFailure, ID: pkt.ID, Body: buildFailure()}.marshal())
		s.failLocked(fmt.Errorf("ppp: authentication failed for %q", username))
		return
	}

	s.username, s.password, s.ntResponse = username, password, ntResponse
	s.send(ProtocolCHAP, cpPacket{
		Code: chapSuccess, ID: pkt.ID,
		Body: buildSuccess(s.authChallenge, peerChallenge, username, password, ntResponse),
	}.marshal())
	s.h.Authenticated(username, password, ntResponse)
	s.phase = phaseIPCP
	s.sendIPCPConfigReq()
}

func (s *ServerSession) sendIPCPConfigReq() {
	opts := []option{{Type: optIPAddress, Value: s.cfg.ServerIP.To4()}}
	s.ipcpReqID = s.nextID()
	s.ipcpConfigReq = cpPacket{Code: codeConfigureRequest, ID: s.ipcpReqID, Body: marshalOptions(opts)}.marshal()
	s.resendIPCPConfigReq()
}

func (s *ServerSession) resendIPCPConfigReq() {
	s.send(ProtocolIPCP, s.ipcpConfigReq)
	s.ipcpRestart.arm(s.withLock, s.resendIPCPConfigReq, func() {
		s.failLocked(fmt.Errorf("ppp: no reply to the IPCP Configure-Request"))
	})
}

func (s *ServerSession) handleIPCP(payload []byte) {
	pkt, ok := parseCP(payload)
	if !ok {
		return
	}
	s.ipcpRestart.alive()
	switch pkt.Code {
	case codeConfigureRequest:
		s.handleIPCPConfigReq(pkt)
	case codeConfigureAck:
		if pkt.ID == s.ipcpReqID {
			s.ipcpRestart.stop()
			s.ipcpLocalOpen = true
			s.maybeIPCPUp()
		}
	case codeConfigureNak, codeConfigureReject:
		// The client disputed our address option. A bare IPCP request is valid and
		// lets the peer's own request finish assigning its address.
		s.ipcpReqID = s.nextID()
		s.ipcpConfigReq = cpPacket{Code: codeConfigureRequest, ID: s.ipcpReqID}.marshal()
		s.resendIPCPConfigReq()
	}
}

func (s *ServerSession) handleIPCPConfigReq(pkt cpPacket) {
	opts, ok := parseOptions(pkt.Body)
	if !ok {
		return
	}
	var nak []option
	for _, o := range opts {
		switch o.Type {
		case optIPAddress:
			if !ipEq(o.Value, s.cfg.ClientIP) {
				nak = append(nak, option{Type: optIPAddress, Value: s.cfg.ClientIP.To4()})
			}
		case optPrimaryDNS:
			if want := s.dnsAt(0); want != nil && !ipEq(o.Value, want) {
				nak = append(nak, option{Type: optPrimaryDNS, Value: want.To4()})
			}
		case optSecondaryDNS:
			if want := s.dnsAt(1); want != nil && !ipEq(o.Value, want) {
				nak = append(nak, option{Type: optSecondaryDNS, Value: want.To4()})
			}
		}
	}
	if len(nak) > 0 {
		s.send(ProtocolIPCP, cpPacket{Code: codeConfigureNak, ID: pkt.ID, Body: marshalOptions(nak)}.marshal())
		return
	}
	s.send(ProtocolIPCP, cpPacket{Code: codeConfigureAck, ID: pkt.ID, Body: pkt.Body}.marshal())
	s.ipcpRemoteOpen = true
	s.maybeIPCPUp()
}

func (s *ServerSession) dnsAt(i int) net.IP {
	if i < len(s.cfg.DNS) {
		return s.cfg.DNS[i]
	}
	return nil
}

func (s *ServerSession) maybeIPCPUp() {
	if s.phase == phaseIPCP && s.ipcpLocalOpen && s.ipcpRemoteOpen {
		s.phase = phaseUp
		s.h.NetworkUp()
	}
}

func ipEq(value []byte, ip net.IP) bool {
	v4 := ip.To4()
	return len(value) == 4 && v4 != nil && value[0] == v4[0] && value[1] == v4[1] && value[2] == v4[2] && value[3] == v4[3]
}
