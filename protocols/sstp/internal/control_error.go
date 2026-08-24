package sstp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

func TerminationError(packet Packet) error {
	var message string
	switch packet.Message {
	case CallAbort:
		message = "sstp: server aborted the call"
	case CallDisconnect:
		message = "sstp: server disconnected the call"
	default:
		return errors.New("sstp: packet is not a termination message")
	}
	value, ok := AttributeValue(packet, AttrStatusInfo)
	if !ok {
		return errors.New(message)
	}
	if len(value) != 8 {
		return fmt.Errorf("%s with malformed status information", message)
	}
	return fmt.Errorf("%s: attribute=%d status=%#08x", message, value[3], binary.BigEndian.Uint32(value[4:8]))
}
