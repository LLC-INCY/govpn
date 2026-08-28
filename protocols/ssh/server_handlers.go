package ssh

import (
	"context"
	"errors"
	"strings"
	"sync"

	gossh "golang.org/x/crypto/ssh"
)

type Server struct {
	Config ServerConfig

	handlersMu      sync.RWMutex
	channelHandlers map[string]ChannelHandler
	globalHandlers  map[string]GlobalRequestHandler
	sessionHandlers map[string]SessionRequestHandler
}

func NewServer(config ServerConfig) *Server {
	return &Server{
		Config:          config,
		channelHandlers: make(map[string]ChannelHandler),
		globalHandlers:  make(map[string]GlobalRequestHandler),
		sessionHandlers: make(map[string]SessionRequestHandler),
	}
}

// RegisterChannelHandler registers a handler for channels such as
// direct-tcpip. The built-in tun@openssh.com and session dispatchers are
// reserved.
func (s *Server) RegisterChannelHandler(channelType string, handler ChannelHandler) error {
	channelType = strings.TrimSpace(channelType)
	if channelType == "" || handler == nil {
		return errors.New("ssh: channel type and handler are required")
	}
	if channelType == "tun@openssh.com" || channelType == "session" {
		return errors.New("ssh: built-in channel type cannot be replaced")
	}
	s.handlersMu.Lock()
	defer s.handlersMu.Unlock()
	if s.channelHandlers == nil {
		s.channelHandlers = make(map[string]ChannelHandler)
	}
	if _, exists := s.channelHandlers[channelType]; exists {
		return errors.New("ssh: channel handler is already registered")
	}
	s.channelHandlers[channelType] = handler
	return nil
}

// RegisterGlobalRequestHandler registers an SSH connection-level request
// handler. The handler owns replies requested by the peer.
func (s *Server) RegisterGlobalRequestHandler(requestType string, handler GlobalRequestHandler) error {
	requestType = strings.TrimSpace(requestType)
	if requestType == "" || handler == nil {
		return errors.New("ssh: global request type and handler are required")
	}
	s.handlersMu.Lock()
	defer s.handlersMu.Unlock()
	if s.globalHandlers == nil {
		s.globalHandlers = make(map[string]GlobalRequestHandler)
	}
	if _, exists := s.globalHandlers[requestType]; exists {
		return errors.New("ssh: global request handler is already registered")
	}
	s.globalHandlers[requestType] = handler
	return nil
}

// RegisterSessionRequestHandler registers a handler for a request on an SSH
// session channel, for example pty-req, shell, exec, or subsystem.
func (s *Server) RegisterSessionRequestHandler(requestType string, handler SessionRequestHandler) error {
	requestType = strings.TrimSpace(requestType)
	if requestType == "" || handler == nil {
		return errors.New("ssh: session request type and handler are required")
	}
	s.handlersMu.Lock()
	defer s.handlersMu.Unlock()
	if s.sessionHandlers == nil {
		s.sessionHandlers = make(map[string]SessionRequestHandler)
	}
	if _, exists := s.sessionHandlers[requestType]; exists {
		return errors.New("ssh: session request handler is already registered")
	}
	s.sessionHandlers[requestType] = handler
	return nil
}

func (s *Server) channelHandler(channelType string) ChannelHandler {
	s.handlersMu.RLock()
	defer s.handlersMu.RUnlock()
	return s.channelHandlers[channelType]
}

func (s *Server) globalHandler(requestType string) GlobalRequestHandler {
	s.handlersMu.RLock()
	defer s.handlersMu.RUnlock()
	return s.globalHandlers[requestType]
}

func (s *Server) sessionHandler(requestType string) SessionRequestHandler {
	s.handlersMu.RLock()
	defer s.handlersMu.RUnlock()
	return s.sessionHandlers[requestType]
}

func (s *Server) hasSessionHandlers() bool {
	s.handlersMu.RLock()
	defer s.handlersMu.RUnlock()
	return len(s.sessionHandlers) != 0
}

func (s *Server) serveGlobalRequests(ctx context.Context, connection *gossh.ServerConn, requests <-chan *gossh.Request) {
	for request := range requests {
		handler := s.globalHandler(request.Type)
		if handler == nil {
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
			continue
		}
		handler(ctx, connection, request)
	}
}

func (s *Server) serveSessionChannel(ctx context.Context, connection *gossh.ServerConn, newChannel gossh.NewChannel) {
	if !s.hasSessionHandlers() {
		_ = newChannel.Reject(gossh.UnknownChannelType, "SSH session channels are not enabled")
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.logf("accept session channel: %v", err)
		return
	}
	defer channel.Close()
	stopContextClose := context.AfterFunc(ctx, func() { _ = channel.Close() })
	defer stopContextClose()
	session := &ServerSession{Connection: connection, Channel: channel}
	for request := range requests {
		handler := s.sessionHandler(request.Type)
		if handler == nil {
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
			continue
		}
		handler(ctx, session, request)
	}
}

func (s *Server) logf(format string, arguments ...any) {
	if s.Config.Logger != nil {
		s.Config.Logger.Printf("[ssh-server] "+format, arguments...)
	}
}
