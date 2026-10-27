package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)}
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) Add(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

type testAuthorityFiles struct {
	certificatePath string
	privateKeyPath  string
	trustBundlePath string
	certificate     *x509.Certificate
	privateKey      *ecdsa.PrivateKey
}

type testCAProfile struct {
	isCA        bool
	keyUsage    x509.KeyUsage
	extKeyUsage []x509.ExtKeyUsage
	notBefore   time.Time
	notAfter    time.Time
}

func writeTestAuthorityFiles(t *testing.T, directory string, now time.Time) testAuthorityFiles {
	t.Helper()
	return writeTestAuthorityFilesWithProfile(t, directory, testCAProfile{
		isCA:      true,
		keyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		notBefore: now.Add(-time.Hour),
		notAfter:  now.Add(365 * 24 * time.Hour),
	})
}

func writeTestAuthorityFilesWithProfile(
	t *testing.T,
	directory string,
	profile testCAProfile,
) testAuthorityFiles {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "BonVoyage test issuer"},
		NotBefore:             profile.notBefore,
		NotAfter:              profile.notAfter,
		BasicConstraintsValid: true,
		IsCA:                  profile.isCA,
		KeyUsage:              profile.keyUsage,
		ExtKeyUsage:           profile.extKeyUsage,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, "issuer.pem")
	privateKeyPath := filepath.Join(directory, "issuer-key.pem")
	trustBundlePath := filepath.Join(directory, "trust.pem")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	writeTestFile(t, certificatePath, certificatePEM, 0o644)
	writeTestFile(t, privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), 0o600)
	writeTestFile(t, trustBundlePath, certificatePEM, 0o644)
	return testAuthorityFiles{
		certificatePath: certificatePath,
		privateKeyPath:  privateKeyPath,
		trustBundlePath: trustBundlePath,
		certificate:     certificate,
		privateKey:      privateKey,
	}
}

func loadTestAuthority(t *testing.T, files testAuthorityFiles, clock *testClock) *Authority {
	t.Helper()
	authority, err := LoadAuthority(AuthorityOptions{
		CertificatePath:     files.certificatePath,
		PrivateKeyPath:      files.privateKeyPath,
		TrustBundlePath:     files.trustBundlePath,
		TrustDomain:         "routesphere.test",
		NodePathPrefix:      "/bonvoyage/node/",
		Clock:               clock.Now,
		DefaultLeafLifetime: 24 * time.Hour,
		MaximumLeafLifetime: 7 * 24 * time.Hour,
		Backdate:            time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func testAuthorityLoader(authority *Authority) AuthorityLoader {
	return func() (*Authority, error) { return authority, nil }
}

func createCSR(t *testing.T, template x509.CertificateRequest) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, privateKey
}

func parseLeaf(t *testing.T, bundle CredentialBundle) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(bundle.ChainPEM))
	if block == nil {
		t.Fatal("credential chain has no leaf PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
