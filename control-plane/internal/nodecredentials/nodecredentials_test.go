package nodecredentials

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	testNodeID      = "node-a"
	testTrustDomain = "routesphere.test"
	testPathPrefix  = "/bonvoyage/nodes/"
)

type testAuthority struct {
	certificate    *x509.Certificate
	privateKey     *ecdsa.PrivateKey
	certificatePEM []byte
}

type credentialFixture struct {
	now       time.Time
	request   *CertificateRequest
	publicKey *ecdsa.PublicKey
	authority *testAuthority
	bundle    *bonvoyagev1.NodeCredentialBundle
	options   ValidationOptions
}

func TestGenerateProducesMinimalSignedP256CSR(t *testing.T) {
	request, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	privateKey, _, err := parsePrivateKey(request.PrivateKeyPEM())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(request.CSRDER())
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() || !publicKey.Equal(&privateKey.PublicKey) {
		t.Fatal("CSR is not bound to the generated ECDSA P-256 key")
	}
	if len(csr.Extensions) != 0 || len(csr.ExtraExtensions) != 0 || len(csr.Attributes) != 0 ||
		len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 ||
		len(csr.URIs) != 0 {
		t.Fatalf("CSR requested issuer-owned fields: %#v", csr)
	}
	firstKey := request.PrivateKeyPEM()
	firstKey[0] ^= 0xff
	if bytes.Equal(firstKey, request.PrivateKeyPEM()) {
		t.Fatal("private key accessor exposed mutable internal storage")
	}
	firstCSR := request.CSRDER()
	firstCSR[0] ^= 0xff
	if bytes.Equal(firstCSR, request.CSRDER()) {
		t.Fatal("CSR accessor exposed mutable internal storage")
	}
}

func TestValidateAcceptsExactNodeCredentialBundle(t *testing.T) {
	fixture := newCredentialFixture(t, "gen-valid-001", nil)
	generation, err := Validate(fixture.bundle, fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	manifest := generation.Manifest()
	if manifest.CredentialGeneration != fixture.bundle.GetCredentialGeneration() ||
		manifest.NodeID != testNodeID || manifest.TrustDomain != testTrustDomain ||
		manifest.NodePathPrefix != testPathPrefix ||
		manifest.SPIFFEID != "spiffe://routesphere.test/bonvoyage/nodes/node-a" ||
		manifest.SerialNumber != fixture.bundle.GetSerialNumber() ||
		manifest.NotBefore != fixture.bundle.GetNotBefore().AsTime() ||
		manifest.NotAfter != fixture.bundle.GetNotAfter().AsTime() ||
		manifest.RenewAfter != fixture.bundle.GetRenewAfter().AsTime() ||
		manifest.ServerTime != fixture.bundle.GetServerTime().AsTime() {
		t.Fatalf("validated manifest does not exactly reflect the response: %#v", manifest)
	}
}

func TestValidateAcceptsLeafAndIntermediateWithSeparateRootTrust(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestAuthority(t, now)
	issuer := newIntermediateAuthority(t, now, root)
	fixture := newCredentialFixtureAt(t, "gen-intermediate-001", issuer, now)
	fixture.issueLeaf(t, fixture.leafTemplate(t), issuer, root.certificatePEM)
	if _, err := Validate(fixture.bundle, fixture.options); err != nil {
		t.Fatalf("Validate() rejected a conventional leaf/intermediate response with a separate root bundle: %v", err)
	}
}

func TestValidateRejectsCredentialContractViolations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *credentialFixture)
	}{
		{
			name: "private key mismatch",
			mutate: func(t *testing.T, fixture *credentialFixture) {
				other, err := Generate()
				if err != nil {
					t.Fatal(err)
				}
				fixture.options.PrivateKeyPEM = other.PrivateKeyPEM()
			},
		},
		{
			name: "wrong SPIFFE ID",
			mutate: func(t *testing.T, fixture *credentialFixture) {
				template := fixture.leafTemplate(t)
				template.URIs = []*url.URL{mustURL(t, "spiffe://routesphere.test/bonvoyage/nodes/node-b")}
				fixture.issueLeaf(t, template, fixture.authority, fixture.authority.certificatePEM)
			},
		},
		{
			name: "multiple URI SANs",
			mutate: func(t *testing.T, fixture *credentialFixture) {
				template := fixture.leafTemplate(t)
				template.URIs = append(template.URIs, mustURL(t, "spiffe://routesphere.test/bonvoyage/nodes/node-b"))
				fixture.issueLeaf(t, template, fixture.authority, fixture.authority.certificatePEM)
			},
		},
		{
			name: "wrong extended key usage",
			mutate: func(t *testing.T, fixture *credentialFixture) {
				template := fixture.leafTemplate(t)
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
				fixture.issueLeaf(t, template, fixture.authority, fixture.authority.certificatePEM)
			},
		},
		{
			name: "additional extended key usage",
			mutate: func(t *testing.T, fixture *credentialFixture) {
				template := fixture.leafTemplate(t)
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
				fixture.issueLeaf(t, template, fixture.authority, fixture.authority.certificatePEM)
			},
		},
		{
			name: "CA leaf",
			mutate: func(t *testing.T, fixture *credentialFixture) {
				template := fixture.leafTemplate(t)
				template.IsCA = true
				template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
				fixture.issueLeaf(t, template, fixture.authority, fixture.authority.certificatePEM)
			},
		},
		{
			name: "wrong issuer",
			mutate: func(t *testing.T, fixture *credentialFixture) {
				otherAuthority := newTestAuthority(t, fixture.now)
				fixture.issueLeaf(t, fixture.leafTemplate(t), otherAuthority, fixture.authority.certificatePEM)
			},
		},
		{
			name: "expired leaf",
			mutate: func(t *testing.T, fixture *credentialFixture) {
				template := fixture.leafTemplate(t)
				template.NotBefore = fixture.now.Add(-2 * time.Hour)
				template.NotAfter = fixture.now.Add(-time.Hour)
				fixture.issueLeaf(t, template, fixture.authority, fixture.authority.certificatePEM)
			},
		},
		{
			name: "not yet valid leaf",
			mutate: func(t *testing.T, fixture *credentialFixture) {
				template := fixture.leafTemplate(t)
				template.NotBefore = fixture.now.Add(time.Hour)
				template.NotAfter = fixture.now.Add(25 * time.Hour)
				fixture.issueLeaf(t, template, fixture.authority, fixture.authority.certificatePEM)
			},
		},
		{
			name: "certificate digest mismatch",
			mutate: func(_ *testing.T, fixture *credentialFixture) {
				fixture.bundle.CertificateSha256[0] ^= 0xff
			},
		},
		{
			name: "issuer digest mismatch",
			mutate: func(_ *testing.T, fixture *credentialFixture) {
				fixture.bundle.IssuerSha256[0] ^= 0xff
			},
		},
		{
			name: "serial mismatch",
			mutate: func(_ *testing.T, fixture *credentialFixture) {
				fixture.bundle.SerialNumber = "deadbeef"
			},
		},
		{
			name: "not-before mismatch",
			mutate: func(_ *testing.T, fixture *credentialFixture) {
				fixture.bundle.NotBefore = timestamppb.New(fixture.bundle.GetNotBefore().AsTime().Add(time.Second))
			},
		},
		{
			name: "not-after mismatch",
			mutate: func(_ *testing.T, fixture *credentialFixture) {
				fixture.bundle.NotAfter = timestamppb.New(fixture.bundle.GetNotAfter().AsTime().Add(time.Second))
			},
		},
		{
			name: "renew-after mismatch",
			mutate: func(_ *testing.T, fixture *credentialFixture) {
				fixture.bundle.RenewAfter = timestamppb.New(fixture.bundle.GetRenewAfter().AsTime().Add(time.Second))
			},
		},
		{
			name: "unsafe generation",
			mutate: func(_ *testing.T, fixture *credentialFixture) {
				fixture.bundle.CredentialGeneration = "../escape"
			},
		},
		{
			name: "server clock beyond bound",
			mutate: func(_ *testing.T, fixture *credentialFixture) {
				fixture.bundle.ServerTime = timestamppb.New(fixture.now.Add(31 * time.Second))
			},
		},
		{
			name: "unknown protobuf field",
			mutate: func(_ *testing.T, fixture *credentialFixture) {
				fixture.bundle.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
			},
		},
		{
			name: "trailing untrusted PEM material",
			mutate: func(_ *testing.T, fixture *credentialFixture) {
				fixture.bundle.CertificateChainPem = append(fixture.bundle.CertificateChainPem, []byte("untrusted\n")...)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCredentialFixture(t, "gen-negative-001", nil)
			test.mutate(t, fixture)
			if _, err := Validate(fixture.bundle, fixture.options); err == nil {
				t.Fatal("invalid credential bundle was accepted")
			}
		})
	}
}

func TestPublishReplacementPreservesPermissionsAndImmutableHistory(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "node-credentials")
	firstFixture := newCredentialFixtureAt(t, "gen-first-001", nil, now)
	first := mustValidate(t, firstFixture)
	if err := Publish(root, first); err != nil {
		t.Fatal(err)
	}
	assertCredentialFileModes(t, root, "gen-first-001")
	firstStableKey := mustRead(t, filepath.Join(root, stablePrivateKeyName))

	secondFixture := newCredentialFixtureAt(t, "gen-second-002", nil, now.Add(time.Minute))
	second := mustValidate(t, secondFixture)
	if err := Publish(root, second); err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, second); err != nil {
		t.Fatalf("idempotent publication failed: %v", err)
	}
	current, err := LoadCurrent(root)
	if err != nil {
		t.Fatal(err)
	}
	if current.Manifest().CredentialGeneration != "gen-second-002" {
		t.Fatalf("current generation = %q", current.Manifest().CredentialGeneration)
	}
	if bytes.Equal(firstStableKey, mustRead(t, filepath.Join(root, stablePrivateKeyName))) {
		t.Fatal("stable private key was not replaced")
	}
	if _, err := os.Stat(filepath.Join(root, "generations", "gen-first-001", generationManifestName)); err != nil {
		t.Fatalf("first immutable generation was not retained: %v", err)
	}
	assertCredentialFileModes(t, root, "gen-second-002")
	status, err := Status(root, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if status.CredentialGeneration != "gen-second-002" || status.Expired || status.NotYetValid || status.RenewalDue {
		t.Fatalf("unexpected status: %#v", status)
	}
	expiredStatus, err := Status(root, status.NotAfter)
	if err != nil {
		t.Fatalf("load expired current generation for status: %v", err)
	}
	if !expiredStatus.Expired || !expiredStatus.RenewalDue || expiredStatus.ExpiresIn != 0 {
		t.Fatalf("expired status = %#v", expiredStatus)
	}
	manifestBytes := mustRead(t, filepath.Join(root, currentManifestName))
	if bytes.Contains(manifestBytes, []byte("PRIVATE KEY")) || bytes.Contains(manifestBytes, second.privateKeyPEM) {
		t.Fatal("current manifest contains private key material")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(manifestBytes, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 18 {
		t.Fatalf("strict manifest field count = %d, want 18", len(fields))
	}
}

func TestFailedPublicationRestoresCurrentAndStableFiles(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "node-credentials")
	first := mustValidate(t, newCredentialFixtureAt(t, "gen-first-001", nil, now))
	if err := Publish(root, first); err != nil {
		t.Fatal(err)
	}
	baseline := capturePublishedFiles(t, root)
	second := mustValidate(t, newCredentialFixtureAt(t, "gen-second-002", nil, now.Add(time.Minute)))

	for _, failedStep := range []string{"stable-node", "current-manifest"} {
		t.Run(failedStep, func(t *testing.T) {
			err := publish(root, second, func(step string) error {
				if step == failedStep {
					return errors.New("injected publication failure")
				}
				return nil
			})
			if err == nil {
				t.Fatal("injected publication failure was ignored")
			}
			assertPublishedFiles(t, root, baseline)
			current, loadErr := LoadCurrent(root)
			if loadErr != nil {
				t.Fatalf("previous generation became unusable: %v", loadErr)
			}
			if current.Manifest().CredentialGeneration != "gen-first-001" {
				t.Fatalf("current generation = %q after failed publication", current.Manifest().CredentialGeneration)
			}
		})
	}

	if err := Publish(root, second); err != nil {
		t.Fatalf("retry after retained orphan generation failed: %v", err)
	}
	current, err := LoadCurrent(root)
	if err != nil || current.Manifest().CredentialGeneration != "gen-second-002" {
		t.Fatalf("replacement after retry = %#v, err=%v", current, err)
	}
}

func TestFailedInitialPublicationLeavesNoCurrentOrStableFiles(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "node-credentials")
	generation := mustValidate(t, newCredentialFixtureAt(t, "gen-initial-001", nil, now))
	err := publish(root, generation, func(step string) error {
		if step == "stable-node" {
			return errors.New("injected initial publication failure")
		}
		return nil
	})
	if err == nil {
		t.Fatal("injected initial publication failure was ignored")
	}
	for _, name := range []string{
		currentManifestName, stableTrustBundleName, stableCertificateName, stablePrivateKeyName,
	} {
		if _, statErr := os.Lstat(filepath.Join(root, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("uncommitted file %s remains after rollback: %v", name, statErr)
		}
	}
	if _, loadErr := LoadCurrent(root); !errors.Is(loadErr, ErrNotFound) {
		t.Fatalf("LoadCurrent after failed initial publication = %v", loadErr)
	}
}

func TestStoreRejectsUnsafeRootsSymlinksAndManifestMismatch(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	generation := mustValidate(t, newCredentialFixtureAt(t, "gen-safe-001", nil, now))

	t.Run("symlink root", func(t *testing.T) {
		parent := t.TempDir()
		realRoot := filepath.Join(parent, "real")
		if err := os.Mkdir(realRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "linked")
		if err := os.Symlink(realRoot, link); err != nil {
			t.Fatal(err)
		}
		if err := Publish(link, generation); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("Publish symlink root error = %v", err)
		}
	})

	t.Run("open root permissions", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "open")
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := Publish(root, generation); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("Publish open root error = %v", err)
		}
	})

	t.Run("stable symlink", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "credentials")
		if err := Publish(root, generation); err != nil {
			t.Fatal(err)
		}
		certificatePath := filepath.Join(root, stableCertificateName)
		if err := os.Remove(certificatePath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "generations", "gen-safe-001", stableCertificateName), certificatePath); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCurrent(root); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("LoadCurrent stable symlink error = %v", err)
		}
	})

	t.Run("generation mismatch", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "credentials")
		if err := Publish(root, generation); err != nil {
			t.Fatal(err)
		}
		currentPath := filepath.Join(root, currentManifestName)
		manifest := generation.Manifest()
		manifest.CredentialGeneration = "gen-other-002"
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(currentPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCurrent(root); err == nil {
			t.Fatal("generation/path mismatch was accepted")
		}
	})
}

func newCredentialFixture(t *testing.T, generation string, authority *testAuthority) *credentialFixture {
	t.Helper()
	return newCredentialFixtureAt(t, generation, authority, time.Now().UTC().Truncate(time.Second))
}

func newCredentialFixtureAt(
	t *testing.T,
	generation string,
	authority *testAuthority,
	now time.Time,
) *credentialFixture {
	t.Helper()
	if authority == nil {
		authority = newTestAuthority(t, now)
	}
	request, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(request.CSRDER())
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("generated CSR key is not ECDSA")
	}
	fixture := &credentialFixture{
		now: now.UTC(), request: request, publicKey: publicKey, authority: authority,
		bundle: &bonvoyagev1.NodeCredentialBundle{CredentialGeneration: generation},
		options: ValidationOptions{
			ExpectedNodeID: testNodeID, TrustDomain: testTrustDomain,
			NodePathPrefix: testPathPrefix, PrivateKeyPEM: request.PrivateKeyPEM(),
			Clock: func() time.Time { return now.UTC() }, MaxServerClockSkew: 30 * time.Second,
		},
	}
	fixture.issueLeaf(t, fixture.leafTemplate(t), authority, authority.certificatePEM)
	return fixture
}

func newTestAuthority(t *testing.T, now time.Time) *testAuthority {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	subjectKeyID := sha256.Sum256(publicDER)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "BonVoyage Test Root"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1,
		SubjectKeyId: subjectKeyID[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testAuthority{
		certificate: certificate, privateKey: privateKey,
		certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func newIntermediateAuthority(
	t *testing.T,
	now time.Time,
	root *testAuthority,
) *testAuthority {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	subjectKeyID := sha256.Sum256(publicDER)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "BonVoyage Test Issuer"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          subjectKeyID[:],
		AuthorityKeyId:        root.certificate.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		root.certificate,
		&privateKey.PublicKey,
		root.privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testAuthority{
		certificate:    certificate,
		privateKey:     privateKey,
		certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (fixture *credentialFixture) leafTemplate(t *testing.T) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber: big.NewInt(0x1234), Subject: pkix.Name{CommonName: testNodeID},
		NotBefore: fixture.now.Add(-5 * time.Minute), NotAfter: fixture.now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: false,
		URIs:           []*url.URL{mustURL(t, "spiffe://routesphere.test/bonvoyage/nodes/node-a")},
		AuthorityKeyId: fixture.authority.certificate.SubjectKeyId,
	}
}

func (fixture *credentialFixture) issueLeaf(
	t *testing.T,
	template *x509.Certificate,
	issuer *testAuthority,
	trustPEM []byte,
) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.certificate, fixture.publicKey, issuer.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificateDigest := sha256.Sum256(leaf.Raw)
	issuerDigest := sha256.Sum256(issuer.certificate.Raw)
	renewAfter := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3).UTC()
	fixture.bundle.CertificateChainPem = append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.certificate.Raw})...,
	)
	fixture.bundle.TrustBundlePem = append([]byte(nil), trustPEM...)
	fixture.bundle.CertificateSha256 = append([]byte(nil), certificateDigest[:]...)
	fixture.bundle.IssuerSha256 = append([]byte(nil), issuerDigest[:]...)
	fixture.bundle.SerialNumber = leaf.SerialNumber.Text(16)
	fixture.bundle.NotBefore = timestamppb.New(leaf.NotBefore)
	fixture.bundle.NotAfter = timestamppb.New(leaf.NotAfter)
	fixture.bundle.RenewAfter = timestamppb.New(renewAfter)
	fixture.bundle.ServerTime = timestamppb.New(fixture.now)
}

func mustValidate(t *testing.T, fixture *credentialFixture) *ValidatedGeneration {
	t.Helper()
	bundle := proto.Clone(fixture.bundle).(*bonvoyagev1.NodeCredentialBundle)
	generation, err := Validate(bundle, fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func assertCredentialFileModes(t *testing.T, root, generation string) {
	t.Helper()
	checks := map[string]os.FileMode{
		filepath.Join(root, stablePrivateKeyName):                              0o600,
		filepath.Join(root, currentManifestName):                               0o600,
		filepath.Join(root, "generations", generation, stablePrivateKeyName):   0o600,
		filepath.Join(root, "generations", generation, generationManifestName): 0o600,
	}
	for path, expected := range checks {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != expected {
			t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), expected)
		}
	}
	for _, path := range []string{
		filepath.Join(root, stableCertificateName), filepath.Join(root, stableTrustBundleName),
		filepath.Join(root, "generations", generation, stableCertificateName),
		filepath.Join(root, "generations", generation, stableTrustBundleName),
	} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o022 != 0 {
			t.Fatalf("%s is writable by group or other: %o", path, info.Mode().Perm())
		}
	}
}

func capturePublishedFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for _, name := range []string{
		currentManifestName, stableTrustBundleName, stableCertificateName, stablePrivateKeyName,
	} {
		result[name] = mustRead(t, filepath.Join(root, name))
	}
	return result
}

func assertPublishedFiles(t *testing.T, root string, expected map[string][]byte) {
	t.Helper()
	for name, contents := range expected {
		if actual := mustRead(t, filepath.Join(root, name)); !bytes.Equal(actual, contents) {
			t.Fatalf("published file %s changed after failed publication", name)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
