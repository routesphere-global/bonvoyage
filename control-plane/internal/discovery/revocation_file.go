package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	minimumRevocationValidity = time.Minute
	maximumRevocationValidity = 90 * 24 * time.Hour
)

// InitializeRevocationDocument creates the first empty, freshness-bounded
// revocation snapshot. It refuses to replace an existing path.
func InitializeRevocationDocument(
	path string,
	now time.Time,
	validFor time.Duration,
) (RevocationDocument, error) {
	if err := validateRevocationUpdateInput(path, now, validFor); err != nil {
		return RevocationDocument{}, err
	}
	document := RevocationDocument{
		Version:    1,
		Generation: 1,
		UpdatedAt:  now.UTC(),
		ValidUntil: now.UTC().Add(validFor),
		Revoked:    []RevokedCredential{},
	}
	if err := writeRevocationDocument(path, document, false); err != nil {
		return RevocationDocument{}, err
	}
	return document, nil
}

// RefreshRevocationDocument advances freshness without changing revocations.
// An expired but structurally valid document is recoverable by an operator;
// transport authentication remains fail closed until the refreshed generation
// is atomically published and reloaded.
func RefreshRevocationDocument(
	path string,
	now time.Time,
	validFor time.Duration,
) (RevocationDocument, error) {
	return updateRevocationDocument(path, now, validFor, nil)
}

// AddNodeRevocation atomically revokes every credential for one node. Repeating
// the same request is idempotent but still refreshes the signed-off snapshot
// generation and freshness window.
func AddNodeRevocation(
	path string,
	nodeID string,
	reason string,
	now time.Time,
	validFor time.Duration,
) (RevocationDocument, error) {
	if validateIdentifier("revoked node ID", strings.TrimSpace(nodeID)) != nil ||
		nodeID != strings.TrimSpace(nodeID) || strings.TrimSpace(reason) == "" ||
		len(reason) > 128 {
		return RevocationDocument{}, errors.New("node revocation identity or reason is invalid")
	}
	return updateRevocationDocument(path, now, validFor, func(document *RevocationDocument) {
		for _, revoked := range document.Revoked {
			if revoked.NodeID == nodeID && revoked.CredentialFingerprint == "" &&
				revoked.SerialNumber == "" {
				return
			}
		}
		document.Revoked = append(document.Revoked, RevokedCredential{
			NodeID:    nodeID,
			RevokedAt: now.UTC(),
			Reason:    reason,
		})
	})
}

func updateRevocationDocument(
	path string,
	now time.Time,
	validFor time.Duration,
	mutate func(*RevocationDocument),
) (RevocationDocument, error) {
	if err := validateRevocationUpdateInput(path, now, validFor); err != nil {
		return RevocationDocument{}, err
	}
	contents, err := readLifecycleFile(path, maxRevocationFileBytes, false)
	if err != nil {
		return RevocationDocument{}, err
	}
	document, err := decodeRevocationDocument(contents, now.UTC(), false)
	if err != nil {
		return RevocationDocument{}, err
	}
	if document.Generation == ^uint64(0) {
		return RevocationDocument{}, errors.New("revocation generation is exhausted")
	}
	if mutate != nil {
		mutate(&document)
	}
	document.Generation++
	document.UpdatedAt = now.UTC()
	document.ValidUntil = now.UTC().Add(validFor)
	slices.SortFunc(document.Revoked, func(left, right RevokedCredential) int {
		leftKey := left.NodeID + "\x00" + left.CredentialFingerprint + "\x00" +
			left.IssuerFingerprint + "\x00" + left.SerialNumber
		rightKey := right.NodeID + "\x00" + right.CredentialFingerprint + "\x00" +
			right.IssuerFingerprint + "\x00" + right.SerialNumber
		return strings.Compare(leftKey, rightKey)
	})
	encoded, err := json.Marshal(document)
	if err != nil {
		return RevocationDocument{}, err
	}
	if _, err := parseRevocationDocument(encoded, now.UTC()); err != nil {
		return RevocationDocument{}, fmt.Errorf("validate updated revocation document: %w", err)
	}
	if err := writeRevocationDocument(path, document, true); err != nil {
		return RevocationDocument{}, err
	}
	return document, nil
}

func validateRevocationUpdateInput(path string, now time.Time, validFor time.Duration) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || now.IsZero() ||
		validFor < minimumRevocationValidity || validFor > maximumRevocationValidity {
		return errors.New("revocation path, time, or freshness window is invalid")
	}
	return nil
}

func writeRevocationDocument(
	path string,
	document RevocationDocument,
	replace bool,
) (returnErr error) {
	if info, err := os.Lstat(path); err == nil {
		if !replace || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o022 != 0 {
			return errors.New("revocation destination is unsafe or already exists")
		}
	} else if !errors.Is(err, os.ErrNotExist) || replace {
		return errors.New("revocation destination is unavailable")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("revocation destination parent is unsafe")
	}
	contents, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	file, err := os.CreateTemp(parent, ".revocations-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() {
		if returnErr != nil {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	return nil
}
