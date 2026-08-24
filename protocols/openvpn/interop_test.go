package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOfficialOpenVPNClientHandshake(t *testing.T) {
	binary, err := exec.LookPath("openvpn")
	if err != nil {
		t.Skip("official openvpn binary is not installed")
	}
	ca, caCertificate, caKey := makeCA(t)
	serverCert, serverKey := makeLeaf(t, caCertificate, caKey, true)
	clientCert, clientKey := makeLeaf(t, caCertificate, caKey, false)
	port := testUDPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server, err := NewServer(ServerConfig{
		CA: ca, Cert: serverCert, Key: serverKey, ListenIP: "127.0.0.1",
		ListenPort: port, Pool: "10.77.0.0/24",
	}).Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	directory := t.TempDir()
	writeTestFile(t, directory, "ca.crt", ca)
	writeTestFile(t, directory, "client.crt", clientCert)
	writeTestFile(t, directory, "client.key", clientKey)
	config := fmt.Sprintf(`client
dev null
proto udp
remote 127.0.0.1 %d
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
data-ciphers AES-256-GCM
cipher AES-256-GCM
auth SHA256
nobind
pull
ifconfig-noexec
route-noexec
connect-retry-max 1
verb 3
`, port)
	configPath := writeTestFile(t, directory, "client.ovpn", []byte(config))
	command := exec.CommandContext(ctx, binary, "--config", configPath)
	command.Dir = directory
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = command.Stdout
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	found := false
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		output.WriteString(line + "\n")
		if strings.Contains(line, "Initialization Sequence Completed") {
			found = true
			_ = command.Process.Kill()
			break
		}
	}
	_ = command.Wait()
	if !found {
		waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
		defer waitCancel()
		t.Fatalf("official OpenVPN client did not initialize (server: %v):\n%s", server.Wait(waitCtx), output.String())
	}
}

func TestOfficialOpenVPNServerHandshake(t *testing.T) {
	binary, err := exec.LookPath("openvpn")
	if err != nil {
		t.Skip("official openvpn binary is not installed")
	}
	ca, caCertificate, caKey := makeCA(t)
	serverCert, serverKey := makeLeaf(t, caCertificate, caKey, true)
	clientCert, clientKey := makeLeaf(t, caCertificate, caKey, false)
	port := testUDPPort(t)
	directory := t.TempDir()
	writeTestFile(t, directory, "ca.crt", ca)
	writeTestFile(t, directory, "server.crt", serverCert)
	writeTestFile(t, directory, "server.key", serverKey)
	config := fmt.Sprintf(`mode server
tls-server
dev null
proto udp
local 127.0.0.1
port %d
ca ca.crt
cert server.crt
key server.key
dh none
topology subnet
server 10.78.0.0 255.255.255.0
data-ciphers AES-256-GCM
cipher AES-256-GCM
auth SHA256
ifconfig-noexec
route-noexec
verb 3
`, port)
	configPath := writeTestFile(t, directory, "server.ovpn", []byte(config))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "--config", configPath)
	command.Dir = directory
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = command.Stdout
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()

	ready := make(chan struct{})
	var output bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			output.WriteString(line + "\n")
			if strings.Contains(line, "Initialization Sequence Completed") {
				select {
				case <-ready:
				default:
					close(ready)
				}
			}
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatalf("official OpenVPN server did not start:\n%s", output.String())
	}
	client, err := NewClient(Config{
		Remote: "127.0.0.1", Port: port, CA: ca, Cert: clientCert, Key: clientKey,
		Cipher: "AES-256-GCM",
	}).Start(ctx)
	if err != nil {
		t.Fatalf("Go client failed against official OpenVPN server: %v\n%s", err, output.String())
	}
	_ = client.Close()
}

func makeCA(t *testing.T) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "govpn interop CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), template, key
}

func makeLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, server bool) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageClientAuth
	name := "client"
	if server {
		usage, name = x509.ExtKeyUsageServerAuth, "server"
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func testUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func writeTestFile(t *testing.T, directory, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
