package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	gossh "golang.org/x/crypto/ssh"
)

func loadOrCreateHostKey(path string) ([]byte, error) {
	encoded, err := os.ReadFile(path)
	if err == nil {
		if _, parseErr := gossh.ParsePrivateKey(encoded); parseErr != nil {
			return nil, fmt.Errorf("parse host key %s: %w", path, parseErr)
		}
		return encoded, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read host key %s: %w", path, err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	block, err := gossh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}
	encoded = pem.EncodeToMemory(block)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create host key %s: %w", path, err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write host key %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close host key %s: %w", path, err)
	}
	return encoded, nil
}

type ptyRequest struct {
	Term         string
	Columns      uint32
	Rows         uint32
	WidthPixels  uint32
	HeightPixels uint32
	Modes        string
}

type windowChangeRequest struct {
	Columns      uint32
	Rows         uint32
	WidthPixels  uint32
	HeightPixels uint32
}

type namedRequest struct{ Name string }

func decodePTYRequest(payload []byte) (ptyRequest, error) {
	var request ptyRequest
	if err := gossh.Unmarshal(payload, &request); err != nil {
		return ptyRequest{}, err
	}
	if request.Term == "" {
		request.Term = "xterm-256color"
	}
	if request.Columns == 0 {
		request.Columns = 80
	}
	if request.Rows == 0 {
		request.Rows = 24
	}
	return request, nil
}

func decodeWindowChange(payload []byte) (windowChangeRequest, error) {
	var request windowChangeRequest
	if err := gossh.Unmarshal(payload, &request); err != nil {
		return windowChangeRequest{}, err
	}
	if request.Columns == 0 {
		request.Columns = 80
	}
	if request.Rows == 0 {
		request.Rows = 24
	}
	return request, nil
}

func decodeName(payload []byte) (string, error) {
	var request namedRequest
	if err := gossh.Unmarshal(payload, &request); err != nil {
		return "", err
	}
	return request.Name, nil
}
