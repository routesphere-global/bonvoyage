package nodecredentials

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bonvoyagev1 "github.com/routesphere-global/bonvoyage/api/gen/go/bonvoyage/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	currentManifestName    = "current-generation.json"
	generationManifestName = "manifest.json"
	stableCertificateName  = "node.pem"
	stableTrustBundleName  = "ca.pem"
	stablePrivateKeyName   = "node-key.pem"
	maxManifestBytes       = 64 << 10
)

type publicationFile struct {
	name string
	data []byte
	mode os.FileMode
	step string
}

type fileBackup struct {
	path   string
	exists bool
	data   []byte
	mode   os.FileMode
}

type publicationHook func(step string) error

var publicationMu sync.Mutex

// Publish durably seals generation beneath root and atomically replaces the
// stable files consumed by the dataplane. The current manifest is the final
// commit point. A returned error restores the previous stable generation.
func Publish(root string, generation *ValidatedGeneration) error {
	publicationMu.Lock()
	defer publicationMu.Unlock()
	return publish(root, generation, nil)
}

func publish(root string, generation *ValidatedGeneration, hook publicationHook) error {
	if generation == nil {
		return fmt.Errorf("validated generation is nil: %w", ErrInvalid)
	}
	root, err := secureRoot(root, true)
	if err != nil {
		return err
	}
	if err := validateManifest(generation.manifest); err != nil {
		return fmt.Errorf("validate in-memory generation manifest: %w", err)
	}
	generationsPath := filepath.Join(root, "generations")
	if err := ensurePrivateDirectory(generationsPath); err != nil {
		return err
	}
	if err := sealGeneration(root, generation); err != nil {
		return err
	}

	currentPath := filepath.Join(root, currentManifestName)
	currentBackup, err := backupFile(currentPath, 0o600, false)
	if err != nil {
		return err
	}
	stableSpecs := []publicationFile{
		{name: stableTrustBundleName, data: generation.trustBundlePEM, mode: 0o644, step: "stable-ca"},
		{name: stableCertificateName, data: generation.certificatePEM, mode: 0o644, step: "stable-node"},
		{name: stablePrivateKeyName, data: generation.privateKeyPEM, mode: 0o600, step: "stable-key"},
	}
	stableBackups := make([]fileBackup, 0, len(stableSpecs))
	for _, file := range stableSpecs {
		backup, backupErr := backupFile(filepath.Join(root, file.name), file.mode, currentBackup.exists)
		if backupErr != nil {
			return backupErr
		}
		stableBackups = append(stableBackups, backup)
	}
	if currentBackup.exists {
		if _, loadErr := LoadCurrent(root); loadErr != nil {
			return fmt.Errorf("refuse to replace unusable current generation: %w", loadErr)
		}
	} else {
		for _, backup := range stableBackups {
			if backup.exists {
				return fmt.Errorf("stable file exists without a current manifest: %w", ErrCorrupt)
			}
		}
	}

	rollback := func(cause error) error {
		var rollbackErrors []error
		if restoreErr := restoreBackup(currentBackup); restoreErr != nil {
			rollbackErrors = append(rollbackErrors, restoreErr)
		}
		for _, backup := range stableBackups {
			if restoreErr := restoreBackup(backup); restoreErr != nil {
				rollbackErrors = append(rollbackErrors, restoreErr)
			}
		}
		if syncErr := syncDirectory(root); syncErr != nil {
			rollbackErrors = append(rollbackErrors, syncErr)
		}
		if len(rollbackErrors) != 0 {
			return errors.Join(append([]error{cause}, rollbackErrors...)...)
		}
		return cause
	}

	for _, file := range stableSpecs {
		if hook != nil {
			if hookErr := hook(file.step); hookErr != nil {
				return rollback(fmt.Errorf("publication interrupted before %s: %w", file.step, hookErr))
			}
		}
		if err := writeFileAtomic(filepath.Join(root, file.name), file.data, file.mode); err != nil {
			return rollback(err)
		}
	}
	manifestBytes, err := encodeManifest(generation.manifest)
	if err != nil {
		return rollback(err)
	}
	if hook != nil {
		if hookErr := hook("current-manifest"); hookErr != nil {
			return rollback(fmt.Errorf("publication interrupted before current manifest: %w", hookErr))
		}
	}
	if err := writeFileAtomic(currentPath, manifestBytes, 0o600); err != nil {
		return rollback(err)
	}
	if _, err := LoadCurrent(root); err != nil {
		return rollback(fmt.Errorf("verify published current generation: %w", err))
	}
	return nil
}

// LoadCurrent verifies and loads the current immutable generation. It also
// proves that the stable files exactly match the committed generation.
func LoadCurrent(root string) (*ValidatedGeneration, error) {
	root, err := secureRoot(root, false)
	if err != nil {
		return nil, err
	}
	manifest, _, err := readManifest(filepath.Join(root, currentManifestName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	generation, err := loadGeneration(root, manifest)
	if err != nil {
		return nil, err
	}
	stable := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{stableTrustBundleName, generation.trustBundlePEM, 0o644},
		{stableCertificateName, generation.certificatePEM, 0o644},
		{stablePrivateKeyName, generation.privateKeyPEM, 0o600},
	}
	for _, file := range stable {
		actual, readErr := readSafeFile(filepath.Join(root, file.name), file.mode, artifactLimit(file.name))
		if readErr != nil {
			return nil, fmt.Errorf("read stable %s: %w", file.name, readErr)
		}
		if !bytes.Equal(actual, file.data) {
			return nil, fmt.Errorf("stable %s disagrees with the current generation: %w", file.name, ErrCorrupt)
		}
	}
	return generation, nil
}

// Status verifies current state and projects only bounded, secret-free
// lifecycle metadata at now.
func Status(root string, now time.Time) (CredentialStatus, error) {
	if now.IsZero() {
		return CredentialStatus{}, fmt.Errorf("status time is zero: %w", ErrInvalid)
	}
	generation, err := LoadCurrent(root)
	if err != nil {
		return CredentialStatus{}, err
	}
	manifest := generation.manifest
	now = now.UTC()
	return CredentialStatus{
		CredentialGeneration:   manifest.CredentialGeneration,
		NodeID:                 manifest.NodeID,
		SPIFFEID:               manifest.SPIFFEID,
		CertificateSHA256:      manifest.CertificateSHA256,
		IssuerSHA256:           manifest.IssuerSHA256,
		CertificateChainSHA256: manifest.CertificateChainSHA256,
		TrustBundleSHA256:      manifest.TrustBundleSHA256,
		SerialNumber:           manifest.SerialNumber,
		NotBefore:              manifest.NotBefore,
		NotAfter:               manifest.NotAfter,
		RenewAfter:             manifest.RenewAfter,
		ServerTime:             manifest.ServerTime,
		ExpiresIn:              manifest.NotAfter.Sub(now),
		NotYetValid:            now.Before(manifest.NotBefore),
		RenewalDue:             !now.Before(manifest.RenewAfter),
		Expired:                !now.Before(manifest.NotAfter),
	}, nil
}

func sealGeneration(root string, generation *ValidatedGeneration) (returnErr error) {
	manifest := generation.manifest
	finalPath := filepath.Join(root, "generations", manifest.CredentialGeneration)
	if info, err := os.Lstat(finalPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
			return fmt.Errorf("existing generation directory is unsafe: %w", ErrUnsafePath)
		}
		existing, loadErr := loadGeneration(root, manifest)
		if loadErr != nil {
			return fmt.Errorf("load existing immutable generation: %w", loadErr)
		}
		if !generationEqual(existing, generation) {
			return ErrConflict
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect immutable generation path: %w", err)
	}

	parent := filepath.Join(root, "generations")
	staging, err := os.MkdirTemp(parent, ".staging-")
	if err != nil {
		return fmt.Errorf("create generation staging directory: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := os.Chmod(staging, 0o700); err != nil {
		return fmt.Errorf("restrict generation staging directory: %w", err)
	}
	manifestBytes, err := encodeManifest(manifest)
	if err != nil {
		return err
	}
	files := []publicationFile{
		{name: stablePrivateKeyName, data: generation.privateKeyPEM, mode: 0o600},
		{name: stableCertificateName, data: generation.certificatePEM, mode: 0o644},
		{name: stableTrustBundleName, data: generation.trustBundlePEM, mode: 0o644},
		{name: generationManifestName, data: manifestBytes, mode: 0o600},
	}
	for _, file := range files {
		if err := writeNewFile(filepath.Join(staging, file.name), file.data, file.mode); err != nil {
			return err
		}
	}
	if err := syncDirectory(staging); err != nil {
		return err
	}
	if err := os.Rename(staging, finalPath); err != nil {
		if info, inspectErr := os.Lstat(finalPath); inspectErr == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			existing, loadErr := loadGeneration(root, manifest)
			if loadErr == nil && generationEqual(existing, generation) {
				return nil
			}
		}
		return fmt.Errorf("publish immutable generation directory: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	return nil
}

func loadGeneration(root string, expected Manifest) (*ValidatedGeneration, error) {
	if err := validateManifest(expected); err != nil {
		return nil, err
	}
	directory := filepath.Join(root, "generations", expected.CredentialGeneration)
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("inspect generation directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("generation directory has unsafe type or permissions: %w", ErrUnsafePath)
	}
	stored, _, err := readManifest(filepath.Join(directory, generationManifestName))
	if err != nil {
		return nil, err
	}
	expectedBytes, _ := encodeManifest(expected)
	storedBytes, _ := encodeManifest(stored)
	if !bytes.Equal(expectedBytes, storedBytes) {
		return nil, fmt.Errorf("generation manifest disagrees with current manifest: %w", ErrCorrupt)
	}
	certificatePEM, err := readSafeFile(filepath.Join(root, filepath.FromSlash(stored.CertificatePath)), 0o644, maxCertificateChainBytes)
	if err != nil {
		return nil, err
	}
	trustBundlePEM, err := readSafeFile(filepath.Join(root, filepath.FromSlash(stored.TrustBundlePath)), 0o644, maxTrustBundleBytes)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := readSafeFile(filepath.Join(root, filepath.FromSlash(stored.PrivateKeyPath)), 0o600, maxPrivateKeyBytes)
	if err != nil {
		return nil, err
	}
	chainDigest := sha256.Sum256(certificatePEM)
	trustDigest := sha256.Sum256(trustBundlePEM)
	if hex.EncodeToString(chainDigest[:]) != stored.CertificateChainSHA256 ||
		hex.EncodeToString(trustDigest[:]) != stored.TrustBundleSHA256 {
		return nil, fmt.Errorf("stored certificate or trust artifact digest is not exact: %w", ErrCorrupt)
	}
	certificateDigest, err := hex.DecodeString(stored.CertificateSHA256)
	if err != nil {
		return nil, fmt.Errorf("decode certificate digest: %w", ErrCorrupt)
	}
	issuerDigest, err := hex.DecodeString(stored.IssuerSHA256)
	if err != nil {
		return nil, fmt.Errorf("decode issuer digest: %w", ErrCorrupt)
	}
	bundle := &bonvoyagev1.NodeCredentialBundle{
		CredentialGeneration: stored.CredentialGeneration,
		CertificateChainPem:  certificatePEM,
		TrustBundlePem:       trustBundlePEM,
		CertificateSha256:    certificateDigest,
		IssuerSha256:         issuerDigest,
		SerialNumber:         stored.SerialNumber,
		NotBefore:            timestamppb.New(stored.NotBefore),
		NotAfter:             timestamppb.New(stored.NotAfter),
		RenewAfter:           timestamppb.New(stored.RenewAfter),
		ServerTime:           timestamppb.New(stored.ServerTime),
	}
	validationTime := stored.ServerTime
	if validationTime.Before(stored.NotBefore) {
		validationTime = stored.NotBefore
	}
	if !validationTime.Before(stored.NotAfter) {
		validationTime = stored.NotAfter.Add(-time.Nanosecond)
	}
	skew := clockDistance(validationTime, stored.ServerTime)
	if skew > MaximumServerClockSkew {
		return nil, fmt.Errorf("stored server time cannot validate the generation: %w", ErrCorrupt)
	}
	generation, err := Validate(bundle, ValidationOptions{
		ExpectedNodeID: stored.NodeID, TrustDomain: stored.TrustDomain,
		NodePathPrefix: stored.NodePathPrefix, PrivateKeyPEM: privateKeyPEM,
		Clock: func() time.Time { return validationTime }, MaxServerClockSkew: skew,
	})
	if err != nil {
		return nil, fmt.Errorf("validate stored generation: %w", ErrCorrupt)
	}
	actualBytes, _ := encodeManifest(generation.manifest)
	if !bytes.Equal(actualBytes, storedBytes) {
		return nil, fmt.Errorf("stored credential metadata is not exact: %w", ErrCorrupt)
	}
	return generation, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != manifestSchemaVersion {
		return fmt.Errorf("unsupported manifest schema version: %w", ErrCorrupt)
	}
	if err := validateIdentifier("manifest generation", manifest.CredentialGeneration); err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if err := validateIdentifier("manifest node ID", manifest.NodeID); err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if err := validateTrustDomain(manifest.TrustDomain); err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if err := validateNodePathPrefix(manifest.NodePathPrefix); err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	expectedSPIFFEID := (&urlValue{manifest.TrustDomain, manifest.NodePathPrefix + manifest.NodeID}).String()
	if manifest.SPIFFEID != expectedSPIFFEID || !digestHex(manifest.CertificateSHA256) ||
		!digestHex(manifest.IssuerSHA256) || !digestHex(manifest.CertificateChainSHA256) ||
		!digestHex(manifest.TrustBundleSHA256) || !canonicalHex(manifest.SerialNumber) {
		return fmt.Errorf("manifest identity or certificate metadata is invalid: %w", ErrCorrupt)
	}
	if manifest.NotBefore.IsZero() || !manifest.NotAfter.After(manifest.NotBefore) || !manifest.RenewAfter.Equal(
		manifest.NotBefore.Add(manifest.NotAfter.Sub(manifest.NotBefore)*2/3),
	) || !manifest.RenewAfter.After(manifest.NotBefore) || !manifest.RenewAfter.Before(manifest.NotAfter) ||
		manifest.ServerTime.IsZero() {
		return fmt.Errorf("manifest timestamps are invalid: %w", ErrCorrupt)
	}
	base := filepath.ToSlash(filepath.Join("generations", manifest.CredentialGeneration))
	if manifest.CertificatePath != base+"/node.pem" || manifest.TrustBundlePath != base+"/ca.pem" ||
		manifest.PrivateKeyPath != base+"/node-key.pem" {
		return fmt.Errorf("manifest contains an unexpected artifact path: %w", ErrUnsafePath)
	}
	for _, candidate := range []string{manifest.CertificatePath, manifest.TrustBundlePath, manifest.PrivateKeyPath} {
		if !filepath.IsLocal(filepath.FromSlash(candidate)) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(candidate))) != candidate {
			return fmt.Errorf("manifest path %q is unsafe: %w", candidate, ErrUnsafePath)
		}
	}
	return nil
}

// urlValue avoids reparsing manifest-controlled data after both components
// have passed the package's strict SPIFFE validation.
type urlValue struct {
	host string
	path string
}

func (value urlValue) String() string {
	return "spiffe://" + value.host + value.path
}

func secureRoot(root string, create bool) (string, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", fmt.Errorf("credential root must be one clean absolute path: %w", ErrUnsafePath)
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) && create {
		parent := filepath.Dir(root)
		parentInfo, parentErr := os.Lstat(parent)
		if parentErr != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
			return "", fmt.Errorf("credential root parent is unsafe: %w", ErrUnsafePath)
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			return "", fmt.Errorf("create private credential root: %w", err)
		}
		if err := syncDirectory(parent); err != nil {
			return "", err
		}
		info, err = os.Lstat(root)
	}
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("inspect credential root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return "", fmt.Errorf("credential root must be a real 0700 directory: %w", ErrUnsafePath)
	}
	return root, nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create private credential directory: %w", err)
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect credential directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("credential directory is unsafe: %w", ErrUnsafePath)
	}
	return nil
}

func readManifest(path string) (Manifest, []byte, error) {
	data, err := readSafeFile(path, 0o600, maxManifestBytes)
	if err != nil {
		return Manifest{}, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, nil, fmt.Errorf("decode credential manifest: %w: %v", ErrCorrupt, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, nil, fmt.Errorf("credential manifest contains trailing data: %w", ErrCorrupt)
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, nil, err
	}
	return manifest, data, nil
}

func encodeManifest(manifest Manifest) ([]byte, error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode credential manifest: %w", err)
	}
	return append(data, '\n'), nil
}

func readSafeFile(path string, expectedMode os.FileMode, maxBytes int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("credential file %q has an unsafe type: %w", path, ErrUnsafePath)
	}
	permissions := info.Mode().Perm()
	if expectedMode == 0o600 {
		if permissions != 0o600 {
			return nil, fmt.Errorf("private credential file %q must be 0600, got %o: %w", path, permissions, ErrUnsafePath)
		}
	} else if permissions&0o400 == 0 || permissions&0o022 != 0 {
		return nil, fmt.Errorf("public credential file %q has unsafe permissions %o: %w", path, permissions, ErrUnsafePath)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open credential file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("read credential file: %w", err)
	}
	if len(data) == 0 || len(data) > maxBytes {
		return nil, fmt.Errorf("credential file size is outside 1-%d bytes: %w", maxBytes, ErrCorrupt)
	}
	return data, nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) (returnErr error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create immutable credential file: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = file.Close()
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("set immutable credential file permissions: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write immutable credential file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync immutable credential file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close immutable credential file: %w", err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) (returnErr error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refuse to replace unsafe credential file %q: %w", path, ErrUnsafePath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect credential publication target: %w", err)
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".credential-publication-")
	if err != nil {
		return fmt.Errorf("create credential publication file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if returnErr != nil {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(mode); err != nil {
		return fmt.Errorf("set credential publication permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write credential publication file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync credential publication file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close credential publication file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("atomically replace credential file: %w", err)
	}
	return syncDirectory(directory)
}

func backupFile(path string, mode os.FileMode, required bool) (fileBackup, error) {
	data, err := readSafeFile(path, mode, artifactLimit(filepath.Base(path)))
	if errors.Is(err, os.ErrNotExist) && !required {
		return fileBackup{path: path}, nil
	}
	if err != nil {
		return fileBackup{}, fmt.Errorf("capture credential publication backup: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fileBackup{}, err
	}
	return fileBackup{path: path, exists: true, data: data, mode: info.Mode().Perm()}, nil
}

func restoreBackup(backup fileBackup) error {
	if backup.exists {
		return writeFileAtomic(backup.path, backup.data, backup.mode)
	}
	info, err := os.Lstat(backup.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refuse to remove unsafe rollback target: %w", ErrUnsafePath)
	}
	if err := os.Remove(backup.path); err != nil {
		return fmt.Errorf("remove uncommitted credential file: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open credential directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync credential directory: %w", err)
	}
	return nil
}

func generationEqual(left, right *ValidatedGeneration) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftManifest, _ := encodeManifest(left.manifest)
	rightManifest, _ := encodeManifest(right.manifest)
	return bytes.Equal(leftManifest, rightManifest) &&
		bytes.Equal(left.certificatePEM, right.certificatePEM) &&
		bytes.Equal(left.trustBundlePEM, right.trustBundlePEM) &&
		bytes.Equal(left.privateKeyPEM, right.privateKeyPEM)
}

func artifactLimit(name string) int {
	switch name {
	case stablePrivateKeyName:
		return maxPrivateKeyBytes
	case stableCertificateName:
		return maxCertificateChainBytes
	case stableTrustBundleName:
		return maxTrustBundleBytes
	default:
		return maxManifestBytes
	}
}

func digestHex(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
