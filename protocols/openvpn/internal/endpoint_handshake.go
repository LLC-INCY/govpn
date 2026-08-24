package openvpn

import (
	"errors"
	"net"
)

func ClientEndpoint(conn net.Conn) (*endpoint, error) {
	local, err := NewSessionID()
	if err != nil {
		return nil, err
	}
	reset, err := EncodeControl(Packet{Opcode: ControlHardResetClientV2, LocalSessionID: local, PacketID: 0})
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(reset); err != nil {
		return nil, err
	}
	buffer := make([]byte, 65535)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	response, err := DecodeControl(buffer[:n])
	if err != nil {
		return nil, err
	}
	if response.Opcode != ControlHardResetServerV2 {
		return nil, errors.New("openvpn: expected server hard reset")
	}
	endpoint := newEndpoint(conn, local, response.LocalSessionID)
	if err := endpoint.sendAck(response.PacketID); err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	return endpoint, nil
}

func ServerEndpoint(conn net.Conn, firstDatagram []byte) (*endpoint, error) {
	request, err := DecodeControl(firstDatagram)
	if err != nil {
		return nil, err
	}
	if request.Opcode != ControlHardResetClientV2 {
		return nil, errors.New("openvpn: expected client hard reset")
	}
	local, err := NewSessionID()
	if err != nil {
		return nil, err
	}
	response, err := EncodeControl(Packet{
		Opcode: ControlHardResetServerV2, LocalSessionID: local, RemoteSessionID: request.LocalSessionID,
		Acknowledgments: []uint32{request.PacketID}, PacketID: 0,
	})
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(response); err != nil {
		return nil, err
	}
	return newEndpoint(conn, local, request.LocalSessionID), nil
}
