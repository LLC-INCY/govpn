package openvpn

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/bclswl0827/govpn/internal/packet"
	protocol "github.com/bclswl0827/govpn/protocols/openvpn/internal"
)

func establishServerSession(conn net.Conn, firstDatagram []byte, device *packet.Device, config ServerConfig, tlsConfig *tls.Config, network netip.Prefix, gateway, assigned netip.Addr, network6 netip.Prefix, gateway6, assigned6 netip.Addr) (*transport, error) {
	endpoint, err := protocol.ServerEndpoint(conn, firstDatagram)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = endpoint.Close()
		}
	}()
	control := protocol.NewControlConn(endpoint)
	tlsConn := tls.Server(control, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("openvpn: TLS handshake: %w", err)
	}
	reader := bufio.NewReader(tlsConn)
	clientMessage, err := protocol.ReadKeyMethod(reader, true)
	if err != nil {
		return nil, err
	}
	clientCiphers := parsePeerDataCiphers(clientMessage.PeerInfo)
	selectedCipher, err := selectDataCipher(effectiveServerDataCiphers(config), clientCiphers, config.DataCipherFallback)
	if err != nil {
		return nil, err
	}
	serverSource, err := protocol.NewServerKeySource()
	if err == nil {
		err = protocol.WriteKeyMethod(tlsConn, protocol.KeyMethodMessage{Source: serverSource, Options: serverOptions(config, selectedCipher)}, true)
	}
	if err != nil {
		return nil, err
	}
	command, err := protocol.ReadCommand(reader, 4096)
	if err != nil {
		return nil, err
	}
	if command != "PUSH_REQUEST" {
		return nil, errors.New("openvpn: expected PUSH_REQUEST")
	}
	push := "PUSH_REPLY"
	if network.IsValid() {
		netmask := prefixNetmask(network.Bits())
		push += fmt.Sprintf(",ifconfig %s %s,route-gateway %s,topology subnet", assigned, netmask, gateway)
	}
	if network6.IsValid() {
		push += fmt.Sprintf(",ifconfig-ipv6 %s/%d %s", assigned6, network6.Bits(), gateway6)
	}
	push += fmt.Sprintf(",cipher %s", selectedCipher)
	if err := protocol.WriteCommand(tlsConn, push); err != nil {
		return nil, err
	}
	keys := protocol.DeriveKeys(clientMessage.Source, serverSource, endpoint.RemoteSessionID(), endpoint.LocalSessionID())
	sendCipher, err := newDataCipher(selectedCipher, effectiveServerAuth(config), keys.Server)
	if err != nil {
		return nil, err
	}
	receiveCipher, err := newDataCipher(selectedCipher, effectiveServerAuth(config), keys.Client)
	if err != nil {
		return nil, err
	}
	closeOnError = false
	return newTransport(endpoint, device, sendCipher, receiveCipher, false, 0, config.Compression, 0, 0, config.Logger), nil
}
