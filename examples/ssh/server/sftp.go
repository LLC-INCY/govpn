package main

import (
	"context"
	"errors"
	"io"
	"log"

	sshvpn "github.com/bclswl0827/govpn/protocols/ssh"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

func sftpHandler(logger *log.Logger) sshvpn.SessionRequestHandler {
	return func(_ context.Context, session *sshvpn.ServerSession, request *gossh.Request) {
		subsystem, err := decodeName(request.Payload)
		if err != nil || subsystem != "sftp" {
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
			return
		}
		server, err := sftp.NewServer(session.Channel)
		if err != nil {
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
			_ = session.Channel.Close()
			return
		}
		if request.WantReply {
			_ = request.Reply(true, nil)
		}
		logger.Printf("SFTP started: user=%s", session.Connection.User())
		if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) {
			logger.Printf("SFTP ended: user=%s error=%v", session.Connection.User(), err)
		}
		_ = server.Close()
		_ = session.Channel.Close()
		logger.Printf("SFTP closed: user=%s", session.Connection.User())
	}
}
