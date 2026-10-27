package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthorityIssuesStrictNodeLeaf(t *testing.T) {
	clock := newTestClock()
	files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, files, clock)
	csr, _ := createCSR(t, x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored-csr-name"}})

	bundle, err := authority.Issue(context.Background(), IssueRequest{NodeID: "edge-sg-01", CSRDER: csr})
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseLeaf(t, bundle)
	if got, want := leaf.URIs[0].String(), "spiffe://routesphere.test/bonvoyage/node/edge-sg-01"; got != want {
		t.Fatalf("SPIFFE ID = %q, want %q", got, want)
	}
	if leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("issued leaf profile = CA:%v key:%v EKU:%v", leaf.IsCA, leaf.KeyUsage, leaf.ExtKeyUsage)
	}
	if len(leaf.URIs) != 1 || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		t.Fatalf("issued leaf names = URI:%v DNS:%v IP:%v email:%v", leaf.URIs, leaf.DNSNames, leaf.IPAddresses, leaf.EmailAddresses)
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		t.Fatalf("issued public key = %T", leaf.PublicKey)
	}
	if leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.BitLen() > 128 {
		t.Fatalf("serial = %s (%d bits)", leaf.SerialNumber, leaf.SerialNumber.BitLen())
	}
	if bundle.GenerationID == "" || bundle.LeafFingerprint != fingerprint(leaf.Raw) ||
		bundle.IssuerFingerprint != fingerprint(files.certificate.Raw) || bundle.Serial != leaf.SerialNumber.Text(16) {
		t.Fatalf("bundle metadata = %#v", bundle)
	}
	wantRenewAfter := bundle.NotBefore.Add(bundle.NotAfter.Sub(bundle.NotBefore) * 2 / 3)
	if !bundle.RenewAfter.Equal(wantRenewAfter) {
		t.Fatalf("renew after = %s, want %s", bundle.RenewAfter, wantRenewAfter)
	}
	if !strings.Contains(bundle.ChainPEM, "BEGIN CERTIFICATE") ||
		bundle.TrustBundlePEM != authority.TrustBundlePEM() ||
		authority.IssuerFingerprint() != bundle.IssuerFingerprint {
		t.Fatalf("public bundle or authority metadata mismatch")
	}
}

func TestAuthorityRejectsUnsafeCAMaterial(t *testing.T) {
	clock := newTestClock()
	t.Run("private key permissions", func(t *testing.T) {
		files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
		if err := os.Chmod(files.privateKeyPath, 0o640); err != nil {
			t.Fatal(err)
		}
		_, err := LoadAuthority(testAuthorityOptions(files, clock))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("certificate permissions", func(t *testing.T) {
		files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
		if err := os.Chmod(files.certificatePath, 0o664); err != nil {
			t.Fatal(err)
		}
		_, err := LoadAuthority(testAuthorityOptions(files, clock))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("symlink private key", func(t *testing.T) {
		directory := t.TempDir()
		files := writeTestAuthorityFiles(t, directory, clock.Now())
		link := filepath.Join(directory, "issuer-key-link.pem")
		if err := os.Symlink(files.privateKeyPath, link); err != nil {
			t.Fatal(err)
		}
		options := testAuthorityOptions(files, clock)
		options.PrivateKeyPath = link
		_, err := LoadAuthority(options)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("key mismatch", func(t *testing.T) {
		files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		otherDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, files.privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}), 0o600)
		_, err = LoadAuthority(testAuthorityOptions(files, clock))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("non CA", func(t *testing.T) {
		files := writeTestAuthorityFilesWithProfile(t, t.TempDir(), testCAProfile{
			isCA: false, keyUsage: x509.KeyUsageDigitalSignature,
			notBefore: clock.Now().Add(-time.Hour), notAfter: clock.Now().Add(24 * time.Hour),
		})
		_, err := LoadAuthority(testAuthorityOptions(files, clock))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("missing cert sign", func(t *testing.T) {
		files := writeTestAuthorityFilesWithProfile(t, t.TempDir(), testCAProfile{
			isCA: true, keyUsage: x509.KeyUsageDigitalSignature,
			notBefore: clock.Now().Add(-time.Hour), notAfter: clock.Now().Add(24 * time.Hour),
		})
		_, err := LoadAuthority(testAuthorityOptions(files, clock))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("server only EKU", func(t *testing.T) {
		files := writeTestAuthorityFilesWithProfile(t, t.TempDir(), testCAProfile{
			isCA: true, keyUsage: x509.KeyUsageCertSign,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			notBefore:   clock.Now().Add(-time.Hour), notAfter: clock.Now().Add(24 * time.Hour),
		})
		_, err := LoadAuthority(testAuthorityOptions(files, clock))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unanchored issuer", func(t *testing.T) {
		files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
		unrelated := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
		trust, err := os.ReadFile(unrelated.certificatePath)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, files.trustBundlePath, trust, 0o644)
		_, err = LoadAuthority(testAuthorityOptions(files, clock))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("non CA trust certificate", func(t *testing.T) {
		files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
		leafFiles := writeTestAuthorityFilesWithProfile(t, t.TempDir(), testCAProfile{
			isCA: false, keyUsage: x509.KeyUsageDigitalSignature,
			notBefore: clock.Now().Add(-time.Hour), notAfter: clock.Now().Add(24 * time.Hour),
		})
		trust, err := os.ReadFile(leafFiles.certificatePath)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, files.trustBundlePath, trust, 0o644)
		_, err = LoadAuthority(testAuthorityOptions(files, clock))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("non PEM trust suffix", func(t *testing.T) {
		files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
		trust, err := os.ReadFile(files.trustBundlePath)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, files.trustBundlePath, append(trust, []byte("garbage")...), 0o644)
		_, err = LoadAuthority(testAuthorityOptions(files, clock))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("duplicate trust certificate", func(t *testing.T) {
		files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
		trust, err := os.ReadFile(files.trustBundlePath)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, files.trustBundlePath, append(trust, trust...), 0o644)
		_, err = LoadAuthority(testAuthorityOptions(files, clock))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestAuthorityRejectsUntrustedCSRClaimsAndKeys(t *testing.T) {
	clock := newTestClock()
	files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, files, clock)
	validCSR, _ := createCSR(t, x509.CertificateRequest{})

	tests := []struct {
		name string
		csr  func(*testing.T) []byte
	}{
		{
			name: "DNS SAN",
			csr: func(t *testing.T) []byte {
				der, _ := createCSR(t, x509.CertificateRequest{DNSNames: []string{"attacker.example"}})
				return der
			},
		},
		{
			name: "CA extension",
			csr: func(t *testing.T) []byte {
				der, _ := createCSR(t, x509.CertificateRequest{ExtraExtensions: []pkix.Extension{{
					Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}, Critical: true,
				}}})
				return der
			},
		},
		{
			name: "RSA key",
			csr: func(t *testing.T) []byte {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
				if err != nil {
					t.Fatal(err)
				}
				return der
			},
		},
		{
			name: "tampered signature",
			csr: func(t *testing.T) []byte {
				result := append([]byte(nil), validCSR...)
				result[len(result)-1] ^= 0xff
				return result
			},
		},
		{
			name: "PEM instead of DER",
			csr: func(t *testing.T) []byte {
				return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: validCSR})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := authority.Issue(context.Background(), IssueRequest{NodeID: "node-a", CSRDER: test.csr(t)})
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestAuthorityBoundsValidityAndPolicy(t *testing.T) {
	clock := newTestClock()
	files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, files, clock)
	csr, _ := createCSR(t, x509.CertificateRequest{})
	if _, err := authority.Issue(context.Background(), IssueRequest{
		NodeID: "node-a", CSRDER: csr, Lifetime: 8 * 24 * time.Hour,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized lifetime error = %v", err)
	}
	if _, err := authority.Issue(context.Background(), IssueRequest{
		NodeID: "node-a", CSRDER: csr, Lifetime: time.Minute,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("undersized lifetime error = %v", err)
	}
}

func testAuthorityOptions(files testAuthorityFiles, clock *testClock) AuthorityOptions {
	return AuthorityOptions{
		CertificatePath: files.certificatePath, PrivateKeyPath: files.privateKeyPath,
		TrustBundlePath: files.trustBundlePath, TrustDomain: "routesphere.test",
		NodePathPrefix: "/bonvoyage/node/", Clock: clock.Now,
		DefaultLeafLifetime: 24 * time.Hour, MaximumLeafLifetime: 7 * 24 * time.Hour,
		Backdate: time.Minute,
	}
}

func TestAuthorityRejectsWrongCurveCA(t *testing.T) {
	clock := newTestClock()
	directory := t.TempDir()
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "wrong curve"},
		NotBefore: clock.Now().Add(-time.Hour), NotAfter: clock.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	files := testAuthorityFiles{
		certificatePath: filepath.Join(directory, "ca.pem"),
		privateKeyPath:  filepath.Join(directory, "key.pem"),
		trustBundlePath: filepath.Join(directory, "trust.pem"),
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	writeTestFile(t, files.certificatePath, certificatePEM, 0o644)
	writeTestFile(t, files.privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	writeTestFile(t, files.trustBundlePath, certificatePEM, 0o644)
	_, err = LoadAuthority(testAuthorityOptions(files, clock))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v", err)
	}
}
