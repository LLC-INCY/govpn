//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"

	sshvpn "github.com/bclswl0827/govpn/protocols/ssh"
	"github.com/creack/pty"
	gossh "golang.org/x/crypto/ssh"
)

const shellStateKey = "easysshd.shell-state"

type shellState struct {
	mu      sync.Mutex
	close   sync.Once
	term    string
	columns uint16
	rows    uint16
	command *exec.Cmd
	pty     *os.File
	session *sshvpn.ServerSession
	logger  *log.Logger
}

func registerSessionHandlers(server *sshvpn.Server, shell string, logger *log.Logger) error {
	registrations := []struct {
		requestType string
		handler     sshvpn.SessionRequestHandler
	}{
		{requestType: "pty-req", handler: handlePTYRequest(logger)},
		{requestType: "window-change", handler: handleWindowChange(logger)},
		{requestType: "signal", handler: handleSignal(logger)},
		{requestType: "shell", handler: handleShell(shell, logger)},
	}
	for _, registration := range registrations {
		if err := server.RegisterSessionRequestHandler(registration.requestType, registration.handler); err != nil {
			return err
		}
	}
	return nil
}

func handlePTYRequest(logger *log.Logger) sshvpn.SessionRequestHandler {
	return func(_ context.Context, session *sshvpn.ServerSession, request *gossh.Request) {
		ptyRequest, err := decodePTYRequest(request.Payload)
		if err != nil {
			reply(request, false)
			return
		}
		state := sessionShellState(session, logger)
		state.mu.Lock()
		state.term = ptyRequest.Term
		state.columns = terminalDimension(ptyRequest.Columns)
		state.rows = terminalDimension(ptyRequest.Rows)
		state.mu.Unlock()
		reply(request, true)
	}
}

func handleWindowChange(logger *log.Logger) sshvpn.SessionRequestHandler {
	return func(_ context.Context, session *sshvpn.ServerSession, request *gossh.Request) {
		window, err := decodeWindowChange(request.Payload)
		if err != nil {
			reply(request, false)
			return
		}
		state := sessionShellState(session, logger)
		state.resize(terminalDimension(window.Columns), terminalDimension(window.Rows))
		reply(request, true)
	}
}

func handleSignal(logger *log.Logger) sshvpn.SessionRequestHandler {
	return func(_ context.Context, session *sshvpn.ServerSession, request *gossh.Request) {
		name, err := decodeName(request.Payload)
		if err != nil {
			reply(request, false)
			return
		}
		state := sessionShellState(session, logger)
		state.signal(sshSignal(name))
		reply(request, true)
	}
}

func handleShell(shell string, logger *log.Logger) sshvpn.SessionRequestHandler {
	return func(ctx context.Context, session *sshvpn.ServerSession, request *gossh.Request) {
		state := sessionShellState(session, logger)
		if err := state.start(ctx, shell); err != nil {
			logger.Printf("start shell: user=%s error=%v", session.Connection.User(), err)
			reply(request, false)
			return
		}
		reply(request, true)
		logger.Printf("shell started: user=%s", session.Connection.User())
		go state.bridge()
	}
}

func sessionShellState(session *sshvpn.ServerSession, logger *log.Logger) *shellState {
	if value, ok := session.Value(shellStateKey); ok {
		return value.(*shellState)
	}
	state := &shellState{
		term: "xterm-256color", columns: 80, rows: 24,
		session: session, logger: logger,
	}
	session.SetValue(shellStateKey, state)
	return state
}

func (s *shellState) start(ctx context.Context, shell string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.command != nil {
		return errors.New("shell is already running")
	}
	command := exec.CommandContext(ctx, shell)
	command.Env = append(os.Environ(), "TERM="+s.term)
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	terminal, err := pty.Start(command)
	if err != nil {
		return err
	}
	if err := pty.Setsize(terminal, &pty.Winsize{Cols: s.columns, Rows: s.rows}); err != nil {
		_ = terminal.Close()
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
		return err
	}
	s.command = command
	s.pty = terminal
	return nil
}

func (s *shellState) resize(columns, rows uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if columns != 0 {
		s.columns = columns
	}
	if rows != 0 {
		s.rows = rows
	}
	if s.pty != nil {
		_ = pty.Setsize(s.pty, &pty.Winsize{Cols: s.columns, Rows: s.rows})
	}
}

func (s *shellState) signal(signal os.Signal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.command != nil && s.command.Process != nil {
		_ = s.command.Process.Signal(signal)
	}
}

func (s *shellState) bridge() {
	s.mu.Lock()
	terminal := s.pty
	channel := s.session.Channel
	s.mu.Unlock()
	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(terminal, channel)
		done <- err
	}()
	go func() {
		_, err := io.Copy(channel, terminal)
		done <- err
	}()
	if err := <-done; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
		s.logger.Printf("shell stream ended: user=%s error=%v", s.session.Connection.User(), err)
	}
	s.closeAll()
	s.logger.Printf("shell closed: user=%s", s.session.Connection.User())
}

func (s *shellState) closeAll() {
	s.close.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.pty != nil {
			_ = s.pty.Close()
		}
		_ = s.session.Channel.Close()
		if s.command != nil && s.command.Process != nil {
			_ = s.command.Process.Kill()
			_, _ = s.command.Process.Wait()
		}
	})
}

func sshSignal(name string) os.Signal {
	switch name {
	case "INT":
		return syscall.SIGINT
	case "KILL":
		return syscall.SIGKILL
	case "HUP":
		return syscall.SIGHUP
	default:
		return syscall.SIGTERM
	}
}

func terminalDimension(value uint32) uint16 {
	if value > uint32(^uint16(0)) {
		return ^uint16(0)
	}
	return uint16(value)
}

func reply(request *gossh.Request, accepted bool) {
	if request.WantReply {
		_ = request.Reply(accepted, nil)
	}
}
