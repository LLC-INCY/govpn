package softether

import (
	"errors"
	"strings"
	"testing"

	protocol "github.com/bclswl0827/govpn/protocols/softether/internal"
)

func TestServerErrorMessages(t *testing.T) {
	for code, message := range map[uint32]string{
		3:  "connection was interrupted",
		8:  "virtual Hub was not found",
		9:  "authentication failed",
		15: "too many connections",
	} {
		if err := serverError(code); !strings.Contains(err.Error(), message) {
			t.Fatalf("serverError(%d) = %q", code, err)
		}
	}
}

func TestAuthenticateErrorCodes(t *testing.T) {
	challenge := []byte("01234567890123456789")
	tests := []struct {
		name string
		pack *protocol.Pack
		code uint32
	}{
		{name: "invalid method", pack: loginPack("noop", "DEFAULT", "alice", 1), code: 4},
		{name: "unknown hub", pack: loginPack("login", "MISSING", "alice", 1), code: 8},
		{name: "unknown user", pack: loginPack("login", "DEFAULT", "mallory", 1), code: 9},
		{name: "unsupported auth", pack: loginPack("login", "DEFAULT", "alice", 99), code: 7},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := authenticate(test.pack, ServerConfig{Hub: "DEFAULT", Users: map[string]string{"alice": "secret"}}, challenge)
			var protocolError *softEtherError
			if !errors.As(err, &protocolError) {
				t.Fatalf("authenticate() error = %v, want SoftEther code %d", err, test.code)
			}
			if protocolError.code != test.code {
				t.Fatalf("authenticate() code = %d, want %d", protocolError.code, test.code)
			}
		})
	}
}

func loginPack(method, hub, username string, authType uint32) *protocol.Pack {
	pack := protocol.NewPack()
	pack.AddString("method", method)
	pack.AddString("hubname", hub)
	pack.AddString("username", username)
	pack.AddInt("authtype", authType)
	return pack
}
