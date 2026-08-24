package softether

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/bclswl0827/govpn/internal/packet"
	protocol "github.com/bclswl0827/govpn/protocols/softether/internal"
)

type serverTransport struct {
	listener  net.Listener
	device    *packet.Device
	tlsConfig *tls.Config
	mu        sync.Mutex
	conn      net.Conn
	once      sync.Once
}

func newServerTransport(listener net.Listener, device *packet.Device, tlsConfig *tls.Config) *serverTransport {
	return &serverTransport{listener: listener, device: device, tlsConfig: tlsConfig}
}

func (s *serverTransport) Close() error {
	var err error
	s.once.Do(func() {
		s.mu.Lock()
		conn := s.conn
		s.mu.Unlock()
		if conn != nil {
			err = conn.Close()
		}
		err = errors.Join(err, s.listener.Close(), s.device.Close())
	})
	return err
}

func (s *serverTransport) accept(config ServerConfig, localIP, assigned netip.Addr, prefixBits int, dns []netip.Addr, done chan<- error) {
	rawConn, err := s.listener.Accept()
	if err != nil {
		done <- normalizeError(err)
		return
	}
	s.mu.Lock()
	s.conn = rawConn
	s.mu.Unlock()
	conn := tls.Server(rawConn, s.tlsConfig)
	if err = conn.Handshake(); err != nil {
		_ = s.Close()
		done <- normalizeError(err)
		return
	}
	reader := bufio.NewReader(conn)
	useEncrypt := true
	useCompress := false
	if err = protocol.ReadSignatureRequest(reader); err == nil {
		challenge := make([]byte, 20)
		_, err = io.ReadFull(rand.Reader, challenge)
		if err == nil {
			hello := protocol.NewPack()
			hello.AddString("hello", "govpn SoftEther VPN Server")
			hello.AddInt("version", 100)
			hello.AddInt("build", 1)
			hello.AddData("random", challenge)
			err = protocol.WritePackResponse(conn, hello)
		}
		if err == nil {
			var login *protocol.Pack
			login, err = protocol.ReadPackRequest(reader)
			if err == nil {
				err = authenticate(login, config, challenge)
				if err == nil {
					useEncrypt = login.GetInt("use_encrypt") != 0 && !config.DisableEncryption
					useCompress = login.GetInt("use_compress") != 0 && config.EnableCompression
				} else {
					var loginError *softEtherError
					if errors.As(err, &loginError) {
						errorPack := protocol.NewPack()
						errorPack.AddInt("error", loginError.code)
						_ = protocol.WritePackResponse(conn, errorPack)
					}
				}
			}
		}
		if err == nil {
			welcome := welcomePack(config, useEncrypt, useCompress)
			err = protocol.WritePackResponse(conn, welcome)
		}
	}
	if err != nil {
		_ = s.Close()
		done <- err
		return
	}
	streamReader, streamWriter := io.Reader(reader), io.Writer(conn)
	if !useEncrypt {
		streamReader, streamWriter = rawConn, rawConn
	}
	stream := protocol.NewFrameStream(streamReader, streamWriter, useCompress)
	serverMAC := [6]byte{0x02, 0x53, 0x45, 0, 0, 1}
	localPrefix := netip.PrefixFrom(localIP, prefixBits)
	dhcpReply := func(frame []byte) ([]byte, netip.Addr, [6]byte, bool) {
		return protocol.DHCPServerReply(frame, serverMAC, localIP, assigned, prefixBits, dns)
	}
	newTransport(rawConn, s.device, stream, serverMAC, localPrefix, netip.Addr{}, [6]byte{}, dhcpReply).run(done)
}

func authenticate(login *protocol.Pack, config ServerConfig, challenge []byte) error {
	if login.GetString("method") != "login" {
		return &softEtherError{code: 4, message: "invalid login method"}
	}
	if login.GetString("hubname") != config.Hub {
		return &softEtherError{code: 8, message: "hub not found"}
	}
	username := login.GetString("username")
	switch login.GetInt("authtype") {
	case protocol.AuthAnonymous:
		if !config.AnonymousUsers[username] {
			return &softEtherError{code: 9, message: "authentication failed"}
		}
	case protocol.AuthPassword:
		password, ok := config.Users[username]
		if !ok {
			return &softEtherError{code: 9, message: "authentication failed"}
		}
		response := protocol.PasswordResponse(username, password, challenge)
		if subtle.ConstantTimeCompare(login.GetData("secure_password"), response[:]) != 1 {
			return &softEtherError{code: 9, message: "authentication failed"}
		}
	case protocol.AuthPlainPassword:
		password, ok := config.Users[username]
		if !ok {
			return &softEtherError{code: 9, message: "authentication failed"}
		}
		if subtle.ConstantTimeCompare([]byte(login.GetString("plain_password")), []byte(password)) != 1 {
			return &softEtherError{code: 9, message: "authentication failed"}
		}
	case protocol.AuthCertificate:
		if err := authenticateCertificate(login, config.UserCertificates[username], challenge); err != nil {
			return &softEtherError{code: 9, message: "authentication failed"}
		}
	default:
		return &softEtherError{code: 7, message: "unsupported authentication type"}
	}
	return nil
}

func authenticateCertificate(login *protocol.Pack, trustedData, challenge []byte) error {
	if len(trustedData) == 0 {
		return errors.New("no certificate is configured for user")
	}
	presented, err := x509.ParseCertificate(login.GetData("cert"))
	if err != nil {
		return err
	}
	trusted, err := parseCertificate(trustedData)
	if err != nil || !bytes.Equal(presented.Raw, trusted.Raw) {
		return errors.New("client certificate is not trusted")
	}
	publicKey, ok := presented.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("client certificate does not contain an RSA key")
	}
	digest := sha1.Sum(challenge)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, digest[:], login.GetData("sign"))
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	return x509.ParseCertificate(data)
}

type softEtherError struct {
	code    uint32
	message string
}

func (e *softEtherError) Error() string { return "softether: " + e.message }

func welcomePack(config ServerConfig, useEncrypt, useCompress bool) *protocol.Pack {
	pack := protocol.NewPack()
	pack.AddInt("error", 0)
	var identity [8]byte
	_, _ = rand.Read(identity[:])
	pack.AddString("session_name", fmt.Sprintf("SID-GOVPN-%x", identity[:4]))
	pack.AddString("connection_name", fmt.Sprintf("CID-GOVPN-%x", identity[4:]))
	maxConnections := config.MaxConnections
	if maxConnections == 0 {
		maxConnections = 1
	}
	pack.AddInt("max_connection", uint32(maxConnections))
	pack.AddBool("use_encrypt", useEncrypt)
	pack.AddBool("use_compress", useCompress)
	pack.AddInt("half_connection", 0)
	pack.AddInt("timeout", 60000)
	pack.AddInt("qos", 0)
	sessionKey := make([]byte, 20)
	_, _ = rand.Read(sessionKey)
	pack.AddData("session_key", sessionKey)
	pack.AddInt("session_key_32", uint32(sessionKey[0])<<24|uint32(sessionKey[1])<<16|uint32(sessionKey[2])<<8|uint32(sessionKey[3]))
	protocol.AddPolicy(pack, protocol.Policy{Access: true, MaxConnection: uint32(maxConnections), Timeout: 60, MaxMAC: 32, MaxIP: 32, MaxIPv6: 32})
	pack.AddInt("vlan_id", 0)
	pack.AddBool("enable_udp_recovery", false)
	return pack
}
