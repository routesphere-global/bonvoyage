package adminapi

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// LoadTLSConfig constructs the dedicated Admin TLS 1.3 boundary and rejects
// any trust anchor or server leaf also supplied for node-facing listeners.
func LoadTLSConfig(
	certificatePath string,
	keyPath string,
	clientCAPath string,
	serverName string,
	forbiddenCAPaths []string,
	forbiddenServerCertificatePaths []string,
) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load Admin server certificate and key: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return nil, errors.New("Admin server certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse Admin server leaf certificate: %w", err)
	}
	if leaf.IsCA || leaf.VerifyHostname(serverName) != nil || !permitsServerAuth(leaf) {
		return nil, errors.New("Admin server certificate is not valid for the configured DNS identity")
	}
	certificate.Leaf = leaf
	clientContents, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("read Admin client CA bundle: %w", err)
	}
	adminCAs, err := parseCertificateBundle(clientContents, true)
	if err != nil {
		return nil, fmt.Errorf("parse Admin client CA bundle: %w", err)
	}
	for _, path := range forbiddenCAPaths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read forbidden node trust bundle: %w", err)
		}
		certificates, err := parseCertificateBundle(contents, false)
		if err != nil {
			return nil, fmt.Errorf("parse forbidden node trust bundle: %w", err)
		}
		if bundlesOverlap(adminCAs, certificates) {
			return nil, errors.New("Admin and node client trust anchors overlap")
		}
	}
	for _, path := range forbiddenServerCertificatePaths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read forbidden node server certificate: %w", err)
		}
		certificates, err := parseCertificateBundle(contents, false)
		if err != nil {
			return nil, fmt.Errorf("parse forbidden node server certificate: %w", err)
		}
		for _, candidate := range certificates {
			if bytes.Equal(candidate.Raw, leaf.Raw) {
				return nil, errors.New("Admin and node listeners use the same server certificate")
			}
		}
	}
	pool := x509.NewCertPool()
	for _, authority := range adminCAs {
		pool.AddCert(authority)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: pool, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true,
	}, nil
}

func parseCertificateBundle(contents []byte, requireCA bool) ([]*x509.Certificate, error) {
	remaining := contents
	certificates := make([]*x509.Certificate, 0, 2)
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			if len(strings.TrimSpace(string(remaining))) != 0 {
				return nil, errors.New("certificate bundle contains non-PEM data")
			}
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("certificate bundle contains unsupported PEM block %q", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		if requireCA && (!certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0) {
			return nil, errors.New("Admin client trust bundle contains a non-CA certificate")
		}
		certificates = append(certificates, certificate)
		remaining = rest
	}
	if len(certificates) == 0 {
		return nil, errors.New("certificate bundle is empty")
	}
	return certificates, nil
}

func bundlesOverlap(left, right []*x509.Certificate) bool {
	digests := make(map[[sha256.Size]byte]struct{}, len(left))
	for _, certificate := range left {
		digests[sha256.Sum256(certificate.Raw)] = struct{}{}
	}
	for _, certificate := range right {
		if _, found := digests[sha256.Sum256(certificate.Raw)]; found {
			return true
		}
	}
	return false
}

func permitsServerAuth(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
