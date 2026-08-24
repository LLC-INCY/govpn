package sstp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

const (
	Version = 0x10

	CallConnectRequest = 1
	CallConnectAck     = 2
	CallConnectNak     = 3
	CallConnected      = 4
	CallAbort          = 5
	CallDisconnect     = 6
	CallDisconnectAck  = 7
	EchoRequest        = 8
	EchoResponse       = 9

	AttrEncapsulatedProtocol = 1
	AttrStatusInfo           = 2
	AttrCryptoBinding        = 3
	AttrCryptoBindingRequest = 4

	ProtocolPPP = 1

	MaxPacketSize = 65535
	HTTPPath      = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"
)

type Attribute struct {
	ID    byte
	Value []byte
}

type Packet struct {
	Control    bool
	Message    uint16
	Attributes []Attribute
	Payload    []byte
}

type Framer struct {
	r  *bufio.Reader
	w  io.Writer
	mu sync.Mutex
}

func NewFramer(r io.Reader, w io.Writer) *Framer {
	reader, ok := r.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReader(r)
	}
	return &Framer{r: reader, w: w}
}

func (f *Framer) ReadPacket() (Packet, error) {
	var header [4]byte
	if _, err := io.ReadFull(f.r, header[:]); err != nil {
		return Packet{}, err
	}
	if header[0] != Version || header[1]&^byte(1) != 0 {
		return Packet{}, errors.New("sstp: invalid packet header")
	}
	length := int(binary.BigEndian.Uint16(header[2:]))
	if length < 4 {
		return Packet{}, errors.New("sstp: invalid packet length")
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(f.r, body); err != nil {
		return Packet{}, err
	}
	packet := Packet{Control: header[1]&1 != 0}
	if !packet.Control {
		packet.Payload = body
		return packet, nil
	}
	if len(body) < 4 {
		return Packet{}, errors.New("sstp: truncated control packet")
	}
	packet.Message = binary.BigEndian.Uint16(body[:2])
	count := int(binary.BigEndian.Uint16(body[2:4]))
	body = body[4:]
	packet.Attributes = make([]Attribute, 0, count)
	for range count {
		if len(body) < 4 {
			return Packet{}, errors.New("sstp: truncated attribute")
		}
		length := int(binary.BigEndian.Uint16(body[2:4]))
		if length < 4 || length > len(body) {
			return Packet{}, errors.New("sstp: invalid attribute length")
		}
		packet.Attributes = append(packet.Attributes, Attribute{ID: body[1], Value: append([]byte(nil), body[4:length]...)})
		body = body[length:]
	}
	if len(body) != 0 {
		return Packet{}, errors.New("sstp: trailing control data")
	}
	return packet, nil
}

func (f *Framer) WriteData(payload []byte) error {
	return f.write(false, 0, nil, payload)
}

func (f *Framer) WriteControl(message uint16, attributes ...Attribute) error {
	return f.write(true, message, attributes, nil)
}

func (f *Framer) write(control bool, message uint16, attributes []Attribute, payload []byte) error {
	length := 4 + len(payload)
	if control {
		length += 4
		for _, attribute := range attributes {
			length += 4 + len(attribute.Value)
		}
	}
	if length > MaxPacketSize {
		return errors.New("sstp: packet exceeds 65535 bytes")
	}
	buffer := make([]byte, length)
	buffer[0] = Version
	if control {
		buffer[1] = 1
	}
	binary.BigEndian.PutUint16(buffer[2:4], uint16(length))
	offset := 4
	if control {
		binary.BigEndian.PutUint16(buffer[offset:offset+2], message)
		binary.BigEndian.PutUint16(buffer[offset+2:offset+4], uint16(len(attributes)))
		offset += 4
		for _, attribute := range attributes {
			buffer[offset+1] = attribute.ID
			binary.BigEndian.PutUint16(buffer[offset+2:offset+4], uint16(4+len(attribute.Value)))
			copy(buffer[offset+4:], attribute.Value)
			offset += 4 + len(attribute.Value)
		}
	} else {
		copy(buffer[offset:], payload)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, err := f.w.Write(buffer)
	return err
}

func AttributeValue(packet Packet, id byte) ([]byte, bool) {
	for _, attribute := range packet.Attributes {
		if attribute.ID == id {
			return attribute.Value, true
		}
	}
	return nil, false
}
