package softether

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strings"
)

const (
	ConnectPath = "/vpnsvc/connect.cgi"
	PackPath    = "/vpnsvc/vpn.cgi"
	ContentType = "application/octet-stream"
	MaxPackSize = 65536
	MaxFrames   = 4096

	officialWatermarkSize = 1411
	maxSignatureSize      = officialWatermarkSize + 2000
)

var (
	officialWatermarkPrefix = []byte{'G', 'I', 'F', '8', '9', 'a', 0xc8, 0x00, 0x33, 0x00}
	officialWatermarkSHA256 = [32]byte{
		0x96, 0xa7, 0x06, 0xbb, 0xab, 0x37, 0x8e, 0xc3,
		0x7d, 0xfe, 0xf2, 0x1e, 0x02, 0xb1, 0xa3, 0xc1,
		0x77, 0xfb, 0xeb, 0xef, 0xfa, 0x03, 0x9e, 0xb0,
		0xef, 0xac, 0x91, 0x86, 0x30, 0xdf, 0x12, 0xa0,
	}
)

func WriteSignatureRequest(w io.Writer, host string) error {
	body := []byte("VPNCONNECT")
	_, err := fmt.Fprintf(w, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\nConnection: Keep-Alive\r\n\r\n%s", ConnectPath, host, len(body), body)
	return err
}

func ReadSignatureRequest(r *bufio.Reader) error {
	request, err := http.ReadRequest(r)
	if err != nil {
		return fmt.Errorf("softether: signature request: %w", err)
	}
	defer request.Body.Close()
	if request.Method != http.MethodPost || request.URL.Path != ConnectPath {
		return errors.New("softether: invalid signature request")
	}
	if request.ContentLength <= 0 || request.ContentLength > maxSignatureSize {
		return errors.New("softether: invalid signature length")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxSignatureSize+1))
	if err != nil {
		return err
	}
	legacy := bytes.Equal(body, []byte("VPNCONNECT"))
	official := false
	if len(body) >= officialWatermarkSize && bytes.Equal(body[:len(officialWatermarkPrefix)], officialWatermarkPrefix) {
		official = sha256.Sum256(body[:officialWatermarkSize]) == officialWatermarkSHA256
	}
	if !legacy && !official {
		return errors.New("softether: invalid signature")
	}
	return nil
}

func WritePackRequest(w io.Writer, host string, pack *Pack) error {
	addPadding(pack)
	body, err := pack.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: Keep-Alive\r\n\r\n", PackPath, host, ContentType, len(body))
	if err == nil {
		_, err = w.Write(body)
	}
	return err
}

func ReadPackRequest(r *bufio.Reader) (*Pack, error) {
	request, err := http.ReadRequest(r)
	if err != nil {
		return nil, fmt.Errorf("softether: PACK request: %w", err)
	}
	defer request.Body.Close()
	if request.Method != http.MethodPost || request.URL.Path != PackPath || request.ContentLength <= 0 || request.ContentLength > MaxPackSize {
		return nil, errors.New("softether: invalid PACK request")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, MaxPackSize+1))
	if err != nil {
		return nil, err
	}
	return UnmarshalPack(body)
}

func WritePackResponse(w io.Writer, pack *Pack) error {
	addPadding(pack)
	body, err := pack.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: Keep-Alive\r\n\r\n", ContentType, len(body))
	if err == nil {
		_, err = w.Write(body)
	}
	return err
}

func addPadding(pack *Pack) {
	var sizeBytes [2]byte
	if _, err := rand.Read(sizeBytes[:]); err != nil {
		return
	}
	size := (int(sizeBytes[0])<<8 | int(sizeBytes[1])) % 1000
	padding := make([]byte, size)
	if _, err := rand.Read(padding); err == nil {
		pack.AddData("pencore", padding)
	}
}

func ReadPackResponse(r *bufio.Reader) (*Pack, error) {
	text := textproto.NewReader(r)
	status, err := text.ReadLine()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(status)
	if len(fields) < 2 || fields[0] != "HTTP/1.1" || fields[1] != "200" {
		return nil, fmt.Errorf("softether: server returned %s", status)
	}
	header, err := text.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(header.Get("Content-Type"), ContentType) {
		return nil, errors.New("softether: invalid PACK content type")
	}
	var length int
	if _, err := fmt.Sscan(header.Get("Content-Length"), &length); err != nil || length <= 0 || length > MaxPackSize {
		return nil, errors.New("softether: invalid PACK content length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return UnmarshalPack(body)
}
