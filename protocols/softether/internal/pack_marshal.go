package softether

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

func (p *Pack) MarshalBinary() ([]byte, error) {
	if len(p.elements) > maxElements {
		return nil, errors.New("softether: PACK has too many elements")
	}
	var buffer bytes.Buffer
	writeUint32(&buffer, uint32(len(p.elements)))
	names := make([]string, 0, len(p.elements))
	for name := range p.elements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values := p.elements[name]
		if name == "" || len(name) > maxElementName || len(values) == 0 || len(values) > maxValues {
			return nil, fmt.Errorf("softether: invalid element %q", name)
		}
		typeID := values[0].Type
		writeUint32(&buffer, uint32(len(name)+1))
		buffer.WriteString(name)
		writeUint32(&buffer, uint32(typeID))
		writeUint32(&buffer, uint32(len(values)))
		for _, value := range values {
			if value.Type != typeID {
				return nil, errors.New("softether: mixed value types")
			}
			switch typeID {
			case TypeInt:
				writeUint32(&buffer, value.Int)
			case TypeInt64:
				var data [8]byte
				binary.BigEndian.PutUint64(data[:], value.Int64)
				buffer.Write(data[:])
			case TypeData, TypeString, TypeUTF8:
				if len(value.Bytes) > maxValue {
					return nil, errors.New("softether: value too large")
				}
				length := len(value.Bytes)
				if typeID == TypeUTF8 {
					length++
				}
				writeUint32(&buffer, uint32(length))
				buffer.Write(value.Bytes)
				if typeID == TypeUTF8 {
					buffer.WriteByte(0)
				}
			default:
				return nil, errors.New("softether: unknown value type")
			}
		}
	}
	return buffer.Bytes(), nil
}
