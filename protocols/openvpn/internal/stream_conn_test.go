package openvpn

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestStreamConnPreservesPacketBoundaries(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	stream := NewStreamConn(client)
	written := make(chan error, 1)
	go func() {
		if _, err := stream.Write([]byte("first")); err != nil {
			written <- err
			return
		}
		_, err := stream.Write([]byte("second"))
		written <- err
	}()
	for _, expected := range [][]byte{[]byte("first"), []byte("second")} {
		var header [2]byte
		if _, err := io.ReadFull(server, header[:]); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, int(header[0])<<8|int(header[1]))
		if _, err := io.ReadFull(server, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, expected) {
			t.Fatalf("payload = %q, want %q", payload, expected)
		}
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestStreamConnReadsFragmentedFrame(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	stream := NewStreamConn(client)
	go func() {
		_, _ = server.Write([]byte{0, 5, 'h'})
		_, _ = server.Write([]byte("ello"))
	}()
	buffer := make([]byte, 16)
	n, err := stream.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "hello" {
		t.Fatalf("payload = %q", buffer[:n])
	}
}
