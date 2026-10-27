package adminapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadTLSConfigEnforcesDedicatedAdminTrustAndLeaf(t *testing.T) {
	admin := newAdminTLSFixture(t, "admin.routesphere.test", 10)
	node := newAdminTLSFixture(t, "discovery.routesphere.test", 20)
	config, err := LoadTLSConfig(
		admin.certificatePath, admin.keyPath, admin.caPath, "admin.routesphere.test",
		[]string{node.caPath}, []string{node.certificatePath},
	)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 ||
		config.ClientAuth != tls.RequireAndVerifyClientCert || config.ClientCAs == nil ||
		len(config.NextProtos) != 1 || config.NextProtos[0] != "http/1.1" ||
		!config.SessionTicketsDisabled {
		t.Fatalf("unexpected Admin TLS configuration: %#v", config)
	}

	_, err = LoadTLSConfig(
		admin.certificatePath, admin.keyPath, admin.caPath, "admin.routesphere.test",
		[]string{admin.caPath}, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "trust anchors overlap") {
		t.Fatalf("overlapping trust error = %v", err)
	}
	_, err = LoadTLSConfig(
		admin.certificatePath, admin.keyPath, admin.caPath, "admin.routesphere.test",
		nil, []string{admin.certificatePath},
	)
	if err == nil || !strings.Contains(err.Error(), "same server certificate") {
		t.Fatalf("shared server leaf error = %v", err)
	}
	_, err = LoadTLSConfig(
		admin.certificatePath, admin.keyPath, admin.caPath, "wrong.routesphere.test",
		nil, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "configured DNS identity") {
		t.Fatalf("wrong DNS identity error = %v", err)
	}
}

type adminTLSFixture struct {
	certificatePath string
	keyPath         string
	caPath          string
}

func newAdminTLSFixture(t *testing.T, serverName string, serial int64) adminTLSFixture {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: serverName + " CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(serial + 1), Subject: pkix.Name{CommonName: serverName},
		DNSNames: []string{serverName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(
		rand.Reader, serverTemplate, caCertificate, &serverKey.PublicKey, caKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.pem")
	certificatePath := filepath.Join(directory, "server.pem")
	keyPath := filepath.Join(directory, "server-key.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	certificatePEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...,
	)
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return adminTLSFixture{certificatePath: certificatePath, keyPath: keyPath, caPath: caPath}
}
