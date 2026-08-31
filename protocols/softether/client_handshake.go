package softether

import (
	"bufio"
	"errors"
	"fmt"
	"net"

	protocol "github.com/bclswl0827/govpn/protocols/softether/internal"
)

func clientHandshake(config Config, conn net.Conn, reader *bufio.Reader, host string) (protocol.SessionParameters, error) {
	if err := protocol.WriteSignatureRequest(conn, host); err != nil {
		return protocol.SessionParameters{}, fmt.Errorf("softether: send signature: %w", err)
	}
	hello, err := protocol.ReadPackResponse(reader)
	if err != nil {
		return protocol.SessionParameters{}, fmt.Errorf("softether: hello: %w", err)
	}
	if code := hello.GetInt("error"); code != 0 {
		return protocol.SessionParameters{}, fmt.Errorf("softether: server hello: %w", serverError(code))
	}
	challenge := hello.GetData("random")
	if hello.GetString("hello") == "" || len(challenge) != 20 {
		return protocol.SessionParameters{}, errors.New("softether: invalid server hello")
	}
	login, err := buildClientLogin(config, challenge, conn, hello)
	if err != nil {
		return protocol.SessionParameters{}, err
	}
	if err := protocol.WritePackRequest(conn, host, login); err != nil {
		return protocol.SessionParameters{}, fmt.Errorf("softether: send login: %w", err)
	}
	welcome, err := protocol.ReadPackResponse(reader)
	if err != nil {
		return protocol.SessionParameters{}, fmt.Errorf("softether: welcome: %w", err)
	}
	if code := welcome.GetInt("error"); code != 0 {
		return protocol.SessionParameters{}, fmt.Errorf("softether: login: %w", serverError(code))
	}
	parameters, err := protocol.ParseSessionParameters(welcome)
	if err != nil {
		return protocol.SessionParameters{}, err
	}
	return parameters, nil
}

func serverError(code uint32) error {
	detail := map[uint32]string{
		1: "connection failed", 2: "destination is not a VPN server", 3: "connection was interrupted",
		4: "protocol error", 5: "client is not a VPN client", 6: "operation was canceled",
		7: "authentication type is not supported", 8: "virtual Hub was not found",
		9: "authentication failed", 10: "virtual Hub is stopping", 11: "session was removed",
		12: "access was denied", 13: "session timed out", 14: "invalid protocol",
		15: "too many connections", 16: "virtual Hub is busy", 17: "proxy connection failed",
		18: "proxy error", 19: "proxy authentication failed", 20: "too many sessions for this user",
	}
	if message := detail[code]; message != "" {
		return fmt.Errorf("softether: server error %d: %s", code, message)
	}
	return fmt.Errorf("softether: server error %d", code)
}
