package openvpn

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

func clientTLSConfig(options Config, certificate *tls.Certificate) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if len(options.CA) != 0 && !roots.AppendCertsFromPEM(options.CA) {
		return nil, errors.New("openvpn: CA contains no certificates")
	}
	if len(options.CA) == 0 && len(options.PeerFingerprints) == 0 {
		return nil, errors.New("openvpn: CA or peer-fingerprint is required")
	}
	minVersion := options.TLSVersionMin
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}
	config := &tls.Config{
		MinVersion: minVersion, MaxVersion: options.TLSVersionMax,
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("openvpn: server sent no certificate")
			}
			leaf := state.PeerCertificates[0]
			if len(options.PeerFingerprints) != 0 {
				digest := sha256.Sum256(leaf.Raw)
				matched := false
				for _, allowed := range options.PeerFingerprints {
					matched = matched || bytes.Equal(digest[:], allowed)
				}
				if !matched {
					return errors.New("openvpn: server certificate fingerprint mismatch")
				}
			} else {
				intermediates := x509.NewCertPool()
				for _, certificate := range state.PeerCertificates[1:] {
					intermediates.AddCert(certificate)
				}
				usage := x509.ExtKeyUsageServerAuth
				if options.RemoteCertTLS == "client" {
					usage = x509.ExtKeyUsageClientAuth
				}
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
					return err
				}
			}
			return verifyCertificateName(leaf, options.VerifyX509Name, options.VerifyX509Type)
		},
	}
	if certificate != nil {
		config.Certificates = []tls.Certificate{*certificate}
	}
	return config, nil
}

func verifyCertificateName(certificate *x509.Certificate, expected, matchType string) error {
	if expected == "" {
		return nil
	}
	var actual string
	switch matchType {
	case "", "name":
		actual = certificate.Subject.CommonName
		if actual == expected {
			return nil
		}
	case "name-prefix":
		actual = certificate.Subject.CommonName
		if strings.HasPrefix(actual, expected) {
			return nil
		}
	case "subject":
		actual = certificate.Subject.String()
		if actual == expected {
			return nil
		}
	default:
		return fmt.Errorf("openvpn: unsupported verify-x509-name type %q", matchType)
	}
	return fmt.Errorf("openvpn: certificate name %q does not match %q", actual, expected)
}

func serverTLSConfig(options ServerConfig, certificate tls.Certificate) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(options.CA) {
		return nil, errors.New("openvpn: CA contains no certificates")
	}
	minVersion := options.TLSVersionMin
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}
	clientAuth := tls.RequireAndVerifyClientCert
	if options.VerifyClientCert == "optional" {
		clientAuth = tls.VerifyClientCertIfGiven
	} else if options.VerifyClientCert == "none" {
		clientAuth = tls.NoClientCert
	}
	return &tls.Config{
		MinVersion: minVersion, MaxVersion: options.TLSVersionMax,
		Certificates: []tls.Certificate{certificate}, ClientAuth: clientAuth, ClientCAs: roots,
	}, nil
}
