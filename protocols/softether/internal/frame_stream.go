package softether

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"errors"
	"io"
	"sync"
)

const (
	MaxEthernetFrame = 1600
	MaxKeepAlive     = 512
)

type FrameStream struct {
	r        io.Reader
	w        io.Writer
	compress bool
	mu       sync.Mutex
}

func NewFrameStream(r io.Reader, w io.Writer, compress ...bool) *FrameStream {
	return &FrameStream{r: r, w: w, compress: len(compress) != 0 && compress[0]}
}

func (s *FrameStream) WriteFrames(frames ...[]byte) error {
	if len(frames) > MaxFrames {
		return errors.New("softether: too many frames in batch")
	}
	var buffer bytes.Buffer
	writeUint32(&buffer, uint32(len(frames)))
	for _, frame := range frames {
		if len(frame) > MaxEthernetFrame {
			return errors.New("softether: Ethernet frame is too large")
		}
		block := frame
		if s.compress {
			var compressed bytes.Buffer
			writer := zlib.NewWriter(&compressed)
			if _, err := writer.Write(frame); err != nil {
				return err
			}
			if err := writer.Close(); err != nil {
				return err
			}
			block = compressed.Bytes()
		}
		writeUint32(&buffer, uint32(len(block)))
		buffer.Write(block)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.w.Write(buffer.Bytes())
	return err
}

func (s *FrameStream) WriteKeepAlive() error {
	var buffer bytes.Buffer
	var sizeByte [2]byte
	_, _ = rand.Read(sizeByte[:])
	size := (int(sizeByte[0])<<8 | int(sizeByte[1])) % MaxKeepAlive
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	writeUint32(&buffer, 0xffffffff)
	writeUint32(&buffer, uint32(size))
	buffer.Write(payload)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.w.Write(buffer.Bytes())
	return err
}

func (s *FrameStream) ReadFrames() ([][]byte, error) {
	var count uint32
	for {
		var err error
		count, err = readUint32(s.r)
		if err != nil {
			return nil, err
		}
		if count != 0xffffffff {
			break
		}
		length, err := readUint32(s.r)
		if err != nil || length > MaxKeepAlive {
			return nil, errors.New("softether: invalid keepalive")
		}
		if _, err := io.CopyN(io.Discard, s.r, int64(length)); err != nil {
			return nil, err
		}
	}
	if count > MaxFrames {
		return nil, errors.New("softether: invalid frame count")
	}
	frames := make([][]byte, count)
	for i := range frames {
		length, err := readUint32(s.r)
		if err != nil || length > MaxEthernetFrame*2 {
			return nil, errors.New("softether: invalid frame length")
		}
		block := make([]byte, length)
		if _, err := io.ReadFull(s.r, block); err != nil {
			return nil, err
		}
		if s.compress {
			reader, err := zlib.NewReader(bytes.NewReader(block))
			if err != nil {
				return nil, errors.New("softether: invalid compressed frame")
			}
			frames[i], err = io.ReadAll(io.LimitReader(reader, MaxEthernetFrame+1))
			closeErr := reader.Close()
			if err != nil || closeErr != nil || len(frames[i]) > MaxEthernetFrame {
				return nil, errors.New("softether: invalid compressed frame")
			}
		} else {
			frames[i] = block
		}
	}
	return frames, nil
}
