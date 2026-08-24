package softether

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"

	protocol "github.com/bclswl0827/govpn/protocols/softether/internal"
)

const (
	clientProduct = "govpn SoftEther VPN Client"
	clientVersion = 100
	clientBuild   = 1
)

func buildClientLogin(config Config, challenge []byte, conn net.Conn, hello *protocol.Pack) (*protocol.Pack, error) {
	pack := protocol.NewPack()
	pack.AddString("method", "login")
	pack.AddString("hubname", config.Hub)
	pack.AddString("username", config.Username)
	switch config.AuthType {
	case AuthPassword:
		response := protocol.PasswordResponse(config.Username, config.Password, challenge)
		pack.AddInt("authtype", protocol.AuthPassword)
		pack.AddData("secure_password", response[:])
	case AuthPlainPassword:
		pack.AddInt("authtype", protocol.AuthPlainPassword)
		pack.AddString("plain_password", config.Password)
	case AuthAnonymous:
		pack.AddInt("authtype", protocol.AuthAnonymous)
	case AuthCertificate:
		certificate, signature, err := certificateCredentials(config.ClientCert, config.ClientKey, challenge)
		if err != nil {
			return nil, err
		}
		pack.AddInt("authtype", protocol.AuthCertificate)
		pack.AddData("cert", certificate)
		pack.AddData("sign", signature)
	default:
		return nil, fmt.Errorf("softether: unsupported client authentication type %d", config.AuthType)
	}

	maxConnections := config.MaxConnections
	if maxConnections == 0 {
		maxConnections = 1
	}
	pack.AddString("client_str", clientProduct)
	pack.AddInt("client_ver", clientVersion)
	pack.AddInt("client_build", clientBuild)
	pack.AddInt("protocol", protocol.ProtocolTCP)
	pack.AddString("hello", clientProduct)
	pack.AddInt("version", clientVersion)
	pack.AddInt("build", clientBuild)
	pack.AddInt("client_id", 0)
	pack.AddInt("max_connection", uint32(maxConnections))
	pack.AddBool("use_encrypt", !config.DisableEncryption)
	pack.AddBool("use_compress", config.EnableCompression)
	pack.AddBool("half_connection", config.HalfConnection)
	pack.AddBool("require_bridge_routing_mode", false)
	pack.AddBool("require_monitor_mode", false)
	pack.AddBool("qos", config.EnableQoS)
	pack.AddBool("support_bulk_on_rudp", false)
	pack.AddBool("support_hmac_on_bulk_of_rudp", false)
	pack.AddBool("support_udp_recovery", false)
	pack.AddInt("rudp_bulk_max_version", 0)

	unique := make([]byte, 20)
	if _, err := rand.Read(unique); err != nil {
		return nil, fmt.Errorf("softether: unique client ID: %w", err)
	}
	pack.AddData("unique_id", unique)
	addNodeInfo(pack, config, conn, hello, unique[:16])
	return pack, nil
}

func certificateCredentials(certPEM, keyPEM, challenge []byte) ([]byte, []byte, error) {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, errors.New("softether: certificate authentication requires ClientCert and ClientKey")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("softether: client certificate: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, nil, errors.New("softether: client certificate chain is empty")
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("softether: parse client certificate: %w", err)
	}
	privateKey, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("softether: native certificate authentication requires an RSA private key")
	}
	digest := sha1.Sum(challenge)
	signature, err := privateKey.Sign(rand.Reader, digest[:], crypto.SHA1)
	if err != nil {
		return nil, nil, fmt.Errorf("softether: sign authentication challenge: %w", err)
	}
	return certificate.Raw, signature, nil
}

func addNodeInfo(pack *protocol.Pack, config Config, conn net.Conn, hello *protocol.Pack, unique []byte) {
	hostname, _ := os.Hostname()
	pack.AddString("ClientProductName", clientProduct)
	pack.AddString("ServerProductName", hello.GetString("hello"))
	pack.AddString("ClientOsName", runtime.GOOS)
	pack.AddString("ClientOsVer", runtime.GOARCH)
	pack.AddString("ClientOsProductId", "")
	pack.AddString("ClientHostname", hostname)
	pack.AddString("ServerHostname", config.Server)
	pack.AddString("ProxyHostname", "")
	pack.AddString("HubName", config.Hub)
	pack.AddData("UniqueId", unique)
	pack.AddInt("ClientProductVer", clientVersion)
	pack.AddInt("ClientProductBuild", clientBuild)
	pack.AddInt("ServerProductVer", hello.GetInt("version"))
	pack.AddInt("ServerProductBuild", hello.GetInt("build"))
	pack.AddData("ClientIpAddress6", make([]byte, 16))
	pack.AddData("ServerIpAddress6", make([]byte, 16))
	pack.AddData("ProxyIpAddress6", make([]byte, 16))
	if address, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		pack.AddInt("ClientPort", uint32(address.Port))
	}
	if address, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		pack.AddInt("ServerPort2", uint32(address.Port))
	}
}
