package nodecredentials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

// Generate creates an ECDSA P-256 private key and a signed PKCS#10 request.
// The request deliberately asks for no SAN, CA bit, key usage, extended key
// usage, attributes, or other extensions; the issuer owns the node profile.
func Generate() (*CertificateRequest, error) {
	return generate(rand.Reader)
}

func generate(random io.Reader) (*CertificateRequest, error) {
	if random == nil {
		return nil, fmt.Errorf("random source is nil: %w", ErrInvalid)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA P-256 node key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(random, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create PKCS#10 node request: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated PKCS#10 node request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify generated PKCS#10 node request: %w", err)
	}
	if len(csr.Extensions) != 0 || len(csr.ExtraExtensions) != 0 || len(csr.Attributes) != 0 ||
		len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 ||
		len(csr.URIs) != 0 {
		return nil, fmt.Errorf("generated PKCS#10 request contains issuer-owned fields: %w", ErrInvalid)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal ECDSA P-256 node key: %w", err)
	}
	return &CertificateRequest{
		privateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		csrDER:        append([]byte(nil), csrDER...),
	}, nil
}
