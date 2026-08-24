package sstp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"strings"
)

func WriteClientHTTP(w io.Writer, host string) error {
	_, err := fmt.Fprintf(w, "SSTP_DUPLEX_POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 18446744073709551615\r\n\r\n", HTTPPath, host)
	return err
}

func ReadClientHTTP(r *bufio.Reader) error {
	reader := textproto.NewReader(r)
	line, err := reader.ReadLine()
	if err != nil {
		return fmt.Errorf("sstp: HTTP request: %w", err)
	}
	parts := strings.Fields(line)
	if len(parts) != 3 || parts[0] != "SSTP_DUPLEX_POST" || parts[1] != HTTPPath || parts[2] != "HTTP/1.1" {
		return errors.New("sstp: invalid HTTP tunnel request")
	}
	if _, err := reader.ReadMIMEHeader(); err != nil {
		return fmt.Errorf("sstp: HTTP request headers: %w", err)
	}
	return nil
}

func WriteServerHTTP(w io.Writer) error {
	_, err := io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\nServer: govpn-sstp\r\n\r\n")
	return err
}

func ReadServerHTTP(r *bufio.Reader) error {
	reader := textproto.NewReader(r)
	line, err := reader.ReadLine()
	if err != nil {
		return fmt.Errorf("sstp: HTTP response: %w", err)
	}
	parts := strings.Fields(line)
	if len(parts) < 2 || parts[0] != "HTTP/1.1" || parts[1] != "200" {
		return fmt.Errorf("sstp: server returned %s", strings.TrimSpace(line))
	}
	if _, err := reader.ReadMIMEHeader(); err != nil {
		return fmt.Errorf("sstp: HTTP response headers: %w", err)
	}
	return nil
}
