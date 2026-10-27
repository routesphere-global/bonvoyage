package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var _ Repository = (*FileRepository)(nil)

func TestEnrollmentIsBoundSingleUseAndDurable(t *testing.T) {
	clock := newTestClock()
	authorityFiles := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, authorityFiles, clock)
	repositoryRoot := filepath.Join(t.TempDir(), "nested", "identity")
	repository, err := OpenFileRepository(repositoryRoot, FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := createCSR(t, x509.CertificateRequest{})
	token, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
		NodeID: "node-a", Audience: "bonvoyage-control-plane", TTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token.Value, ".")
	if len(parts) != 3 || parts[0] != "bv1" || parts[1] != token.ID {
		t.Fatalf("token format = %q", token.Value)
	}
	stateBytes, err := os.ReadFile(repository.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateBytes, []byte(parts[2])) || bytes.Contains(stateBytes, []byte(token.Value)) {
		t.Fatal("repository retained raw enrollment secret")
	}
	if !bytes.Contains(stateBytes, []byte(`"secret_sha256"`)) {
		t.Fatal("repository did not retain enrollment digest")
	}

	for name, request := range map[string]EnrollmentRequest{
		"wrong node": {
			Token: token.Value, NodeID: "node-b", Audience: token.Audience, CSRDER: csr,
		},
		"wrong audience": {
			Token: token.Value, NodeID: token.NodeID, Audience: "other-control-plane", CSRDER: csr,
		},
		"wrong secret": {
			Token:  "bv1." + token.ID + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			NodeID: token.NodeID, Audience: token.Audience, CSRDER: csr,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := repository.Enroll(context.Background(), testAuthorityLoader(authority), request); !errors.Is(err, ErrEnrollmentRejected) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := repository.Enroll(context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
		Token: token.Value, NodeID: token.NodeID, Audience: token.Audience, CSRDER: []byte("invalid CSR"),
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid CSR error = %v", err)
	}
	record, err := repository.Enroll(context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
		Token: token.Value, NodeID: token.NodeID, Audience: token.Audience, CSRDER: csr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.NodeID != token.NodeID || record.Bundle.GenerationID == "" {
		t.Fatalf("credential record = %#v", record)
	}
	if _, err := repository.Enroll(context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
		Token: token.Value, NodeID: token.NodeID, Audience: token.Audience, CSRDER: csr,
	}); !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("same-process replay error = %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileRepository(repositoryRoot, FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if _, err := reopened.Enroll(context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
		Token: token.Value, NodeID: token.NodeID, Audience: token.Audience, CSRDER: csr,
	}); !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("post-restart replay error = %v", err)
	}
	restored, err := reopened.CurrentCredential(context.Background(), token.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if restored != record {
		t.Fatalf("restored credential = %#v, want %#v", restored, record)
	}
	assertMode(t, repositoryRoot, 0o700)
	assertMode(t, filepath.Join(repositoryRoot, stateDirectoryName), 0o700)
	assertMode(t, reopened.statePath(), 0o600)
	assertRepositoryContainsNoPrivateMaterial(t, repositoryRoot, authorityFiles.privateKey)
}

func TestEnrollmentRejectsExpiryWithoutConsumingOtherTokens(t *testing.T) {
	clock := newTestClock()
	files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, files, clock)
	repository, err := OpenFileRepository(t.TempDir(), FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	csr, _ := createCSR(t, x509.CertificateRequest{})
	expired, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
		NodeID: "node-expired", Audience: "control-plane", TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	if _, err := repository.Enroll(context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
		Token: expired.Value, NodeID: expired.NodeID, Audience: expired.Audience, CSRDER: csr,
	}); !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("expired token error = %v", err)
	}
	valid, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
		NodeID: "node-valid", Audience: "control-plane", TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Enroll(context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
		Token: valid.Value, NodeID: valid.NodeID, Audience: valid.Audience, CSRDER: csr,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestUnconsumedEnrollmentTokenSurvivesRestart(t *testing.T) {
	clock := newTestClock()
	files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, files, clock)
	root := t.TempDir()
	repository, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	token, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
		NodeID: "node-restart", Audience: "control-plane",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	csr, _ := createCSR(t, x509.CertificateRequest{})
	record, err := reopened.Enroll(context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
		Token: token.Value, NodeID: token.NodeID, Audience: token.Audience, CSRDER: csr,
	})
	if err != nil || record.NodeID != token.NodeID {
		t.Fatalf("post-restart enrollment = %#v, err=%v", record, err)
	}
}

func TestEnrollmentRejectsUnknownTokenBeforeLoadingAuthority(t *testing.T) {
	repository, err := OpenFileRepository(t.TempDir(), FileRepositoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	var loads atomic.Int32
	_, err = repository.Enroll(context.Background(), func() (*Authority, error) {
		loads.Add(1)
		return nil, errors.New("authority loader must not run")
	}, EnrollmentRequest{
		Token:  "bv1." + strings.Repeat("A", 22) + "." + strings.Repeat("A", 43),
		NodeID: "node-a", Audience: "control-plane", CSRDER: []byte("not reached"),
	})
	if !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("unknown-token error = %v", err)
	}
	if loads.Load() != 0 {
		t.Fatalf("authority loads = %d, want 0", loads.Load())
	}
}

func TestEnrollmentAuthorityFailureLeavesTokenRetryable(t *testing.T) {
	clock := newTestClock()
	files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, files, clock)
	repository, err := OpenFileRepository(t.TempDir(), FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	token, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
		NodeID: "node-retry", Audience: "control-plane",
	})
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := createCSR(t, x509.CertificateRequest{})
	loadFailure := errors.New("injected authority load failure")
	_, err = repository.Enroll(context.Background(), func() (*Authority, error) {
		return nil, loadFailure
	}, EnrollmentRequest{
		Token: token.Value, NodeID: token.NodeID, Audience: token.Audience, CSRDER: csr,
	})
	if !errors.Is(err, loadFailure) {
		t.Fatalf("authority failure = %v", err)
	}
	if _, err := repository.Enroll(
		context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
			Token: token.Value, NodeID: token.NodeID, Audience: token.Audience, CSRDER: csr,
		},
	); err != nil {
		t.Fatalf("retry after authority recovery: %v", err)
	}
}

func TestEnrollmentRechecksExpiryAfterAuthorityLoad(t *testing.T) {
	clock := newTestClock()
	files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, files, clock)
	authority.random = failingReader{err: errors.New("signing must not begin for an expired token")}
	repository, err := OpenFileRepository(t.TempDir(), FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	token, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
		NodeID: "node-expiry", Audience: "control-plane", TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := createCSR(t, x509.CertificateRequest{})
	_, err = repository.Enroll(context.Background(), func() (*Authority, error) {
		clock.Add(2 * time.Minute)
		return authority, nil
	}, EnrollmentRequest{
		Token: token.Value, NodeID: token.NodeID, Audience: token.Audience, CSRDER: csr,
	})
	if !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("post-load expiry error = %v", err)
	}
}

func TestEnrollmentCancellationDuringSigningLeavesTokenRetryable(t *testing.T) {
	clock := newTestClock()
	files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, files, clock)
	blocking := &blockingReader{
		reader: rand.Reader, entered: make(chan struct{}), release: make(chan struct{}),
	}
	authority.random = blocking
	repository, err := OpenFileRepository(t.TempDir(), FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	token, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
		NodeID: "node-cancel", Audience: "control-plane",
	})
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := createCSR(t, x509.CertificateRequest{})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, enrollErr := repository.Enroll(ctx, testAuthorityLoader(authority), EnrollmentRequest{
			Token: token.Value, NodeID: token.NodeID, Audience: token.Audience, CSRDER: csr,
		})
		result <- enrollErr
	}()
	select {
	case <-blocking.entered:
	case <-time.After(time.Second):
		t.Fatal("certificate signing did not begin")
	}
	cancel()
	close(blocking.release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled enrollment error = %v", err)
	}
	if _, err := repository.Enroll(
		context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
			Token: token.Value, NodeID: token.NodeID, Audience: token.Audience, CSRDER: csr,
		},
	); err != nil {
		t.Fatalf("retry after cancellation: %v", err)
	}
}

func TestConcurrentEnrollmentConsumesTokenExactlyOnce(t *testing.T) {
	clock := newTestClock()
	files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, files, clock)
	repository, err := OpenFileRepository(t.TempDir(), FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	token, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
		NodeID: "node-concurrent", Audience: "control-plane",
	})
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := createCSR(t, x509.CertificateRequest{})
	const attempts = 24
	var successes atomic.Int32
	var rejections atomic.Int32
	var authorityLoads atomic.Int32
	var unexpectedMu sync.Mutex
	var unexpected []error
	loadAuthority := func() (*Authority, error) {
		authorityLoads.Add(1)
		return authority, nil
	}
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := 0; index < attempts; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, enrollErr := repository.Enroll(context.Background(), loadAuthority, EnrollmentRequest{
				Token: token.Value, NodeID: token.NodeID, Audience: token.Audience, CSRDER: csr,
			})
			switch {
			case enrollErr == nil:
				successes.Add(1)
			case errors.Is(enrollErr, ErrEnrollmentRejected):
				rejections.Add(1)
			default:
				unexpectedMu.Lock()
				unexpected = append(unexpected, enrollErr)
				unexpectedMu.Unlock()
			}
		}()
	}
	close(start)
	group.Wait()
	if successes.Load() != 1 || rejections.Load() != attempts-1 || len(unexpected) != 0 {
		t.Fatalf("successes=%d rejections=%d unexpected=%v", successes.Load(), rejections.Load(), unexpected)
	}
	if authorityLoads.Load() != 1 {
		t.Fatalf("authority loads = %d, want 1", authorityLoads.Load())
	}
}

func TestCredentialRotationAndRevocationSurviveRestart(t *testing.T) {
	clock := newTestClock()
	files := writeTestAuthorityFiles(t, t.TempDir(), clock.Now())
	authority := loadTestAuthority(t, files, clock)
	root := t.TempDir()
	repository, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	firstCSR, _ := createCSR(t, x509.CertificateRequest{})
	token, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
		NodeID: "node-rotate", Audience: "control-plane",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := repository.Enroll(context.Background(), testAuthorityLoader(authority), EnrollmentRequest{
		Token: token.Value, NodeID: token.NodeID, Audience: token.Audience, CSRDER: firstCSR,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondCSR, _ := createCSR(t, x509.CertificateRequest{})
	second, err := repository.RotateCredential(context.Background(), authority, RotationRequest{
		NodeID: token.NodeID, CSRDER: secondCSR,
	})
	if err != nil {
		t.Fatal(err)
	}
	current, err := repository.CurrentCredential(context.Background(), token.NodeID)
	if err != nil || current != second {
		t.Fatalf("current = %#v, err=%v", current, err)
	}
	old, err := repository.CredentialByGeneration(context.Background(), token.NodeID, first.Bundle.GenerationID)
	if err != nil || old != first {
		t.Fatalf("old generation = %#v, err=%v", old, err)
	}
	credentialRevocation, err := repository.RevokeCredential(context.Background(), CredentialRevocationInput{
		NodeID: token.NodeID, GenerationID: first.Bundle.GenerationID, Reason: "superseded and retired",
	})
	if err != nil {
		t.Fatal(err)
	}
	idempotentCredentialRevocation, err := repository.RevokeCredential(context.Background(), CredentialRevocationInput{
		NodeID: token.NodeID, GenerationID: first.Bundle.GenerationID, Reason: "superseded and retired",
	})
	if err != nil || idempotentCredentialRevocation != credentialRevocation {
		t.Fatalf("idempotent credential revocation = %#v, err=%v", idempotentCredentialRevocation, err)
	}
	if _, err := repository.RevokeCredential(context.Background(), CredentialRevocationInput{
		NodeID: token.NodeID, GenerationID: first.Bundle.GenerationID, Reason: "different reason",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed credential revocation error = %v", err)
	}
	bySerial, err := repository.RevocationByIssuerSerial(
		context.Background(), first.Bundle.IssuerFingerprint, first.Bundle.Serial,
	)
	if err != nil || bySerial != credentialRevocation {
		t.Fatalf("issuer/serial revocation = %#v, err=%v", bySerial, err)
	}
	byLeaf, err := repository.RevocationByLeafFingerprint(context.Background(), first.Bundle.LeafFingerprint)
	if err != nil || byLeaf != credentialRevocation {
		t.Fatalf("leaf revocation = %#v, err=%v", byLeaf, err)
	}
	status, err := repository.RevocationStatus(context.Background(), RevocationStatusQuery{
		NodeID: token.NodeID, IssuerFingerprint: first.Bundle.IssuerFingerprint,
		Serial: first.Bundle.Serial, LeafFingerprint: first.Bundle.LeafFingerprint,
	})
	if err != nil || !status.Revoked || status.CredentialRevocation == nil || status.NodeRevocation != nil {
		t.Fatalf("credential status = %#v, err=%v", status, err)
	}
	currentStatus, err := repository.RevocationStatus(context.Background(), RevocationStatusQuery{
		NodeID: token.NodeID, IssuerFingerprint: second.Bundle.IssuerFingerprint,
		Serial: second.Bundle.Serial, LeafFingerprint: second.Bundle.LeafFingerprint,
	})
	if err != nil || currentStatus.Revoked {
		t.Fatalf("current status = %#v, err=%v", currentStatus, err)
	}
	if _, err := repository.RevocationStatus(context.Background(), RevocationStatusQuery{
		NodeID:            token.NodeID,
		IssuerFingerprint: "sha256:" + strings.Repeat("a", sha256.Size*2), Serial: "1",
		LeafFingerprint: "sha256:" + strings.Repeat("b", sha256.Size*2),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown credential status error = %v", err)
	}
	if _, err := repository.RevocationStatus(context.Background(), RevocationStatusQuery{
		NodeID: token.NodeID, IssuerFingerprint: first.Bundle.IssuerFingerprint,
		Serial: first.Bundle.Serial, LeafFingerprint: second.Bundle.LeafFingerprint,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mixed revocation key error = %v", err)
	}
	nodeRevocation, err := repository.RevokeNode(context.Background(), NodeRevocationInput{
		NodeID: token.NodeID, Reason: "operator disabled node",
	})
	if err != nil {
		t.Fatal(err)
	}
	idempotentNodeRevocation, err := repository.RevokeNode(context.Background(), NodeRevocationInput{
		NodeID: token.NodeID, Reason: "operator disabled node",
	})
	if err != nil || idempotentNodeRevocation != nodeRevocation {
		t.Fatalf("idempotent node revocation = %#v, err=%v", idempotentNodeRevocation, err)
	}
	status, err = repository.RevocationStatus(context.Background(), RevocationStatusQuery{
		NodeID: token.NodeID, IssuerFingerprint: second.Bundle.IssuerFingerprint,
		Serial: second.Bundle.Serial, LeafFingerprint: second.Bundle.LeafFingerprint,
	})
	if err != nil || !status.Revoked || status.NodeRevocation == nil || *status.NodeRevocation != nodeRevocation {
		t.Fatalf("node status = %#v, err=%v", status, err)
	}
	if _, err := repository.RotateCredential(context.Background(), authority, RotationRequest{
		NodeID: token.NodeID, CSRDER: secondCSR,
	}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked-node rotation error = %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restoredNodeRevocation, err := reopened.NodeRevocation(context.Background(), token.NodeID)
	if err != nil || restoredNodeRevocation != nodeRevocation {
		t.Fatalf("restored node revocation = %#v, err=%v", restoredNodeRevocation, err)
	}
	restoredCredentialRevocation, err := reopened.RevocationByLeafFingerprint(
		context.Background(), first.Bundle.LeafFingerprint,
	)
	if err != nil || restoredCredentialRevocation != credentialRevocation {
		t.Fatalf("restored credential revocation = %#v, err=%v", restoredCredentialRevocation, err)
	}
}

type failingReader struct {
	err error
}

func (reader failingReader) Read([]byte) (int, error) {
	return 0, reader.err
}

type blockingReader struct {
	reader  io.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (reader *blockingReader) Read(buffer []byte) (int, error) {
	reader.once.Do(func() { close(reader.entered) })
	<-reader.release
	return reader.reader.Read(buffer)
}

func TestRepositoryFilesystemSafetyAndExclusiveLock(t *testing.T) {
	clock := newTestClock()
	t.Run("exclusive process lock", func(t *testing.T) {
		root := t.TempDir()
		first, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now}); !errors.Is(err, ErrLocked) {
			t.Fatalf("second open error = %v", err)
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		second, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		_ = second.Close()
	})
	t.Run("symlink process lock", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(t.TempDir(), "lock-target")
		writeTestFile(t, target, []byte("do not follow"), 0o600)
		if err := os.Symlink(target, filepath.Join(root, lockFileName)); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("symlink root", func(t *testing.T) {
		target := t.TempDir()
		link := filepath.Join(t.TempDir(), "identity-link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileRepository(link, FileRepositoryOptions{Clock: clock.Now}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("symlink state directory", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Symlink(t.TempDir(), filepath.Join(root, stateDirectoryName)); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("symlink state file", func(t *testing.T) {
		root := t.TempDir()
		repository, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		statePath := repository.statePath()
		if err := repository.Close(); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		writeTestFile(t, target, []byte("do not follow"), 0o600)
		if err := os.Remove(statePath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, statePath); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("permissions and atomic files", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		repository, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
			NodeID: "node-a", Audience: "control-plane",
		}); err != nil {
			t.Fatal(err)
		}
		assertMode(t, root, 0o700)
		assertMode(t, filepath.Join(root, stateDirectoryName), 0o700)
		assertMode(t, repository.statePath(), 0o600)
		leftovers, err := filepath.Glob(filepath.Join(root, stateDirectoryName, ".bonvoyage-identity-*"))
		if err != nil || len(leftovers) != 0 {
			t.Fatalf("temporary files = %v, err=%v", leftovers, err)
		}
		_ = repository.Close()
	})
	t.Run("checksum corruption", func(t *testing.T) {
		root := t.TempDir()
		repository, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		statePath := repository.statePath()
		if err := repository.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.Replace(data, []byte(`"generation": 1`), []byte(`"generation": 2`), 1)
		writeTestFile(t, statePath, data, 0o600)
		if _, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsafe state permissions", func(t *testing.T) {
		root := t.TempDir()
		repository, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		statePath := repository.statePath()
		if err := repository.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(statePath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileRepository(root, FileRepositoryOptions{Clock: clock.Now}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestRepositoryValidatesInputsAndClosedState(t *testing.T) {
	clock := newTestClock()
	if _, err := OpenFileRepository(" ", FileRepositoryOptions{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty root error = %v", err)
	}
	if _, err := OpenFileRepository(t.TempDir(), FileRepositoryOptions{MaxEnrollmentTTL: 2 * time.Hour}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized max TTL error = %v", err)
	}
	repository, err := OpenFileRepository(t.TempDir(), FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []EnrollmentTokenInput{
		{NodeID: "-bad", Audience: "control-plane"},
		{NodeID: "node-a", Audience: ""},
		{NodeID: "node-a", Audience: "bad\naudience"},
		{NodeID: "node-a", Audience: "control-plane", TTL: 2 * time.Hour},
	} {
		if _, err := repository.CreateEnrollmentToken(context.Background(), input); !errors.Is(err, ErrInvalid) {
			t.Errorf("input %#v error = %v", input, err)
		}
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
		NodeID: "node-a", Audience: "control-plane",
	}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed repository error = %v", err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

func assertRepositoryContainsNoPrivateMaterial(t *testing.T, root string, privateKey *ecdsa.PrivateKey) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte("PRIVATE KEY")) || bytes.Contains(data, privateKey.D.Bytes()) {
			return fmt.Errorf("private key marker found in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestEnrollmentTokenStateUsesDigestNotSecret(t *testing.T) {
	clock := newTestClock()
	repository, err := OpenFileRepository(t.TempDir(), FileRepositoryOptions{Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	token, err := repository.CreateEnrollmentToken(context.Background(), EnrollmentTokenInput{
		NodeID: "node-digest", Audience: "control-plane",
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token.Value, ".")
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(secret)
	state, err := os.ReadFile(repository.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(state, secret) || !bytes.Contains(state, []byte(fmt.Sprintf("%x", digest))) {
		t.Fatal("state does not contain only the expected enrollment digest")
	}
}
