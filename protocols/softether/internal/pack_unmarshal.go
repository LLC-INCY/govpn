package softether

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

func UnmarshalPack(data []byte) (*Pack, error) {
	reader := bytes.NewReader(data)
	count, err := readUint32(reader)
	if err != nil || count > maxElements {
		return nil, errors.New("softether: invalid PACK element count")
	}
	pack := NewPack()
	for range count {
		nameLength, err := readUint32(reader)
		if err != nil || nameLength < 1 || nameLength > maxElementName+1 {
			return nil, errors.New("softether: invalid element name length")
		}
		name := make([]byte, nameLength-1)
		if _, err := io.ReadFull(reader, name); err != nil {
			return nil, err
		}
		typeID, err := readUint32(reader)
		if err != nil || typeID > TypeInt64 {
			return nil, errors.New("softether: invalid value type")
		}
		valueCount, err := readUint32(reader)
		if err != nil || valueCount == 0 || valueCount > maxValues {
			return nil, errors.New("softether: invalid value count")
		}
		values := make([]Value, valueCount)
		for i := range values {
			values[i].Type = byte(typeID)
			switch typeID {
			case TypeInt:
				values[i].Int, err = readUint32(reader)
			case TypeInt64:
				err = binary.Read(reader, binary.BigEndian, &values[i].Int64)
			case TypeData, TypeString, TypeUTF8:
				var length uint32
				length, err = readUint32(reader)
				if err == nil && length <= maxValue {
					values[i].Bytes = make([]byte, length)
					_, err = io.ReadFull(reader, values[i].Bytes)
				} else if err == nil {
					err = errors.New("value too large")
				}
				if typeID == TypeUTF8 && err == nil {
					if len(values[i].Bytes) == 0 || values[i].Bytes[len(values[i].Bytes)-1] != 0 {
						err = errors.New("invalid UTF-8 value")
					} else {
						values[i].Bytes = values[i].Bytes[:len(values[i].Bytes)-1]
					}
				}
			}
			if err != nil {
				return nil, fmt.Errorf("softether: decode %q: %w", name, err)
			}
		}
		nameString := string(name)
		if _, exists := pack.findName(nameString); exists {
			return nil, fmt.Errorf("softether: duplicate PACK element %q", nameString)
		}
		pack.elements[nameString] = values
	}
	if reader.Len() != 0 {
		return nil, errors.New("softether: trailing PACK bytes")
	}
	return pack, nil
}

func writeUint32(w io.Writer, value uint32) {
	var data [4]byte
	binary.BigEndian.PutUint32(data[:], value)
	_, _ = w.Write(data[:])
}
func readUint32(r io.Reader) (uint32, error) {
	var data [4]byte
	_, err := io.ReadFull(r, data[:])
	return binary.BigEndian.Uint32(data[:]), err
}
