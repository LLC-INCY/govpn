//go:build windows

package main

import (
	"log"

	sshvpn "github.com/bclswl0827/govpn/protocols/ssh"
)

func registerSessionHandlers(_ *sshvpn.Server, _ string, _ *log.Logger) error {
	return nil
}
