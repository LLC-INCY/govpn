package softether

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	officialWatermark = func() []byte {
		data, err := base64.StdEncoding.DecodeString(officialWatermarkBase64)
		if err != nil || len(data) != officialWatermarkSize || sha256.Sum256(data) != officialWatermarkSHA256 {
			panic("softether: invalid embedded watermark")
		}
		return data
	}()
)

const officialWatermarkBase64 = "R0lGODlhyAAzAPIAADY3NHloVICAgK9/W7OondXV1P///wAAACwAAAAAyAAzAAAD/gga3DQKBEFrZTFPEYD5YCiOZGmeaKqubOuaS+MMDCVvVqfp0uv/wKBwyIrcLJzGBccxZiQEonRKrU4FsQ1hyyXUuEkb5hmxms/o9AcrEXQJhXj8DW6Qn+oCgRI17ylqgSwECm5ccoh6em9NdxklcRZxLwWSBpWAIkgWfZgCmnyCBhYjfwIFa0hwIxV9H5ioIX+HibWLfHs8jiOem64rrSCmrJsUscMhFbGBniKersWZIJavxqBwtrZbAxwWjmUhvZvLKp7LweHRp6lu6daCzcnK1dGuvct/rLTZczQ3dt88yJoHQk44TKsK+hIX6lIFEgzbNdPzztkschO3QCLo/rBhx0/sQH6U9lATNoOoann5d+MbKGkbVQkbZ4oaqVLFUHFCgjHatFYVnXG8GfInST7vPE7bku1SvwH+AkSVsWugMnIKJXIc5RGZPF8zYXJ1k5IoQqN9cpogaIocOnM/4YSCVerkpbuJ3kxgMHUMnpfUjMYyO7Rk1nFGRX48Z7gwILgpgj1z55Meqj+R1olgmshpNqgbpP4jA1Htx8SHGbejzBMtZdWxIkreuvahV3oLs5Y9la8uSrwquSVhCRAcJFN9vKIz4BVyWMWvrYqEXBPx7RPmaFc/hbX3WMOyOqdUuYeGmL2jjdfORNTxdNpEhQYlfFTsV+gmGP4quv65/ubNiABXC1T+IDEaDwEUlNBhaZUUDzuuXDcWVs+9FKFhEg6mFHaIvUShPPYEdpB45IEmgHAPEKfEYZUtxlxFzokoGzQcxejRZK+s4hwK4uznYkzktAVRgJME549wAWyhYg3+dfjBdj1VVF0n0eAjE2Q7bmfNjiggUVpQ8kWJ3yu1eCYHFwSK5kZfLB2E3CS8YNYdeB8lpOV/dV5mGJdz8AGnhCeIWKEJ3sUFCT+IoHkkVA+AxmYHokQq6aQjIjrHNg0M0CiBoLVE6aegonFSNnDoJVWanEblj0ChtupqEKOeSZ6Sp6bKqaev5qrrCqVOmVcdtW6K6hi7FmusPnEg/kgWNl0kwamwaepw7LTGJtlFDRyMCiyB0HYqLbXgvpqkIbkMR26ftdrqKLEliFTSmI3Vpwkx9iUzSkifgDSmCnRWoa8PbRAnQRtMeaEuX52qZ+8a0zC88L3u3uswV/M2TMK/Elu8b5cWm7GxClnIMJzI22ia6gIJK3BxxxWzknG+Gmc88Vf4wmwUxO6yJzO8OsMsL8TsjCXxu/1+ELISxJFbMlRGFLfyzA/PG3HEQIPyMMb6kpI1w1NDh1/XqXDdsM5iV232mE2LPDLS5KaKsF9Pyxx1zGVXvS/ZQzvs9cT5au1yyza/LLhifp8t+Ahph7H2P2uqC5rCfLf79+Bj/scnNd0Y02021HJTHvnUHdsc+OgkLLBEDiyZ3m2akO8cesueux416XnLnTnp8I6te9iGUw3Iv6BzboASOZwncgc6tO12617DRPhN8e4N2M169/3Q7xrj/RL1YAe9s8+i4525AaafbnwNGOhgLbTsTh53uIF8nAbxF9hgbmgDL6BoVCpL/j78apAfGspXv9CYKwn5A4AhbtU6ADowDQS0Hw6O4BcjSPARZyDc9971P/l5KVICfGAacDe7tcDufSGUQgpF6LHYuW5r4BOaDFmWtZzZUGy+O0rnWCgKEiYGeGHrWeR++Lnd4ayIZasXDwMYMw3GzocUq5gN2TPFwNmtVXA7XOIIoSe7vAVvc7bTnBRhJzrAaRGEl3OiF4O4O6oN8YtQHOIVz9jDNJYQhoOrIRm9N0MOzk6H46NjuFYoyEKCsGiGTKQiF8nIRjrykZCMpCR1lQAAOw=="

func WriteSignatureRequest(w io.Writer, host string) error {
	var sizeBytes [2]byte
	if _, err := rand.Read(sizeBytes[:]); err != nil {
		return err
	}
	randomSize := (int(sizeBytes[0])<<8 | int(sizeBytes[1])) % 2000
	body := make([]byte, len(officialWatermark)+randomSize)
	copy(body, officialWatermark)
	if _, err := rand.Read(body[len(officialWatermark):]); err != nil {
		return err
	}
	var request bytes.Buffer
	_, _ = fmt.Fprintf(&request, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\nConnection: Keep-Alive\r\n\r\n", ConnectPath, host, len(body))
	request.Write(body)
	return writeAll(w, request.Bytes())
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
	var request bytes.Buffer
	_, _ = fmt.Fprintf(&request, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: Keep-Alive\r\n\r\n", PackPath, host, ContentType, len(body))
	request.Write(body)
	return writeAll(w, request.Bytes())
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
	var response bytes.Buffer
	_, _ = fmt.Fprintf(&response, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: Keep-Alive\r\n\r\n", ContentType, len(body))
	response.Write(body)
	return writeAll(w, response.Bytes())
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
