package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	repositorySchemaVersion = 2
	legacySchemaVersion     = 1
	stateDirectoryName      = "state"
	stateFileName           = "identity.json"
	lockFileName            = ".lock"
	maxStateBytes           = 32 << 20
	maxActiveTokens         = 10_000
	maxCredentialRecords    = 50_000
	maxRevocationRecords    = 50_000
	maxNodeRecords          = 10_000
	maxNodeEvents           = 100_000
	enrollmentTokenBytes    = len("bv1.") + 22 + 1 + 43
)

// FileRepository stores checksummed identity state behind an exclusive process
// lock. Every mutation is written, fsynced, renamed, and directory-fsynced
// before becoming visible in memory.
type FileRepository struct {
	mu               sync.Mutex
	root             string
	clock            func() time.Time
	random           io.Reader
	maxEnrollmentTTL time.Duration
	lock             *repositoryLock
	state            persistedState
	closed           bool
}

type persistedState struct {
	SchemaVersion         uint32                 `json:"schema_version"`
	Generation            uint64                 `json:"generation"`
	EnrollmentTokens      []enrollmentMetadata   `json:"enrollment_tokens,omitempty"`
	Credentials           []CredentialRecord     `json:"credentials,omitempty"`
	CurrentCredentials    []currentCredential    `json:"current_credentials,omitempty"`
	CredentialRevocations []CredentialRevocation `json:"credential_revocations,omitempty"`
	NodeRevocations       []NodeRevocation       `json:"node_revocations,omitempty"`
	Nodes                 []NodeRecord           `json:"nodes,omitempty"`
	NodeEvents            []NodeLifecycleEvent   `json:"node_events,omitempty"`
}

type stateEnvelope struct {
	IntegritySHA256 string         `json:"integrity_sha256"`
	State           persistedState `json:"state"`
}

type enrollmentMetadata struct {
	ID           string     `json:"id"`
	SecretSHA256 string     `json:"secret_sha256"`
	NodeID       string     `json:"node_id"`
	Audience     string     `json:"audience"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	ConsumedAt   *time.Time `json:"consumed_at,omitempty"`
}

type currentCredential struct {
	NodeID       string `json:"node_id"`
	GenerationID string `json:"generation_id"`
}

// OpenFileRepository opens or initializes one private identity repository.
func OpenFileRepository(root string, options FileRepositoryOptions) (_ *FileRepository, returnErr error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("identity repository path is empty: %w", ErrInvalid)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve identity repository path: %w", err)
	}
	if err := ensurePrivateDirectoryTree(absoluteRoot); err != nil {
		return nil, err
	}
	lock, err := acquireRepositoryLock(filepath.Join(absoluteRoot, lockFileName))
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			_ = lock.release()
		}
	}()
	stateDirectory := filepath.Join(absoluteRoot, stateDirectoryName)
	if err := ensurePrivateDirectory(stateDirectory); err != nil {
		return nil, err
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	randomReader := options.Random
	if randomReader == nil {
		randomReader = rand.Reader
	}
	maxTTL := options.MaxEnrollmentTTL
	if maxTTL == 0 {
		maxTTL = MaximumEnrollmentTTL
	}
	if maxTTL <= 0 || maxTTL > MaximumEnrollmentTTL {
		return nil, fmt.Errorf("maximum enrollment TTL exceeds %s: %w", MaximumEnrollmentTTL, ErrInvalid)
	}
	repository := &FileRepository{
		root:             absoluteRoot,
		clock:            clock,
		random:           randomReader,
		maxEnrollmentTTL: maxTTL,
		lock:             lock,
	}
	state, err := repository.loadState()
	if errors.Is(err, os.ErrNotExist) {
		state = persistedState{SchemaVersion: repositorySchemaVersion, Generation: 1}
		if err := repository.writeState(state); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if state.SchemaVersion == legacySchemaVersion {
		state, err = migrateLegacyState(state)
		if err != nil {
			return nil, err
		}
		if err := repository.writeState(state); err != nil {
			return nil, fmt.Errorf("persist identity repository migration: %w", err)
		}
	}
	if err := validateState(state); err != nil {
		return nil, err
	}
	repository.state = state
	return repository, nil
}

// CreateEnrollmentToken creates one short-lived bearer credential. Only its
// SHA-256 secret digest is retained.
func (repository *FileRepository) CreateEnrollmentToken(
	ctx context.Context,
	input EnrollmentTokenInput,
) (EnrollmentToken, error) {
	if err := contextError(ctx); err != nil {
		return EnrollmentToken{}, err
	}
	if err := validateIdentifier("node ID", input.NodeID); err != nil {
		return EnrollmentToken{}, err
	}
	if err := validateText("audience", input.Audience, maxAudienceBytes, true); err != nil {
		return EnrollmentToken{}, err
	}
	if input.TTL < 0 || input.TTL > repository.maxEnrollmentTTL {
		return EnrollmentToken{}, fmt.Errorf("enrollment TTL is outside configured bounds: %w", ErrInvalid)
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return EnrollmentToken{}, err
	}
	if err := contextError(ctx); err != nil {
		return EnrollmentToken{}, err
	}
	if _, _, found := findCurrent(repository.state.CurrentCredentials, input.NodeID); found {
		return EnrollmentToken{}, fmt.Errorf("node %q is already enrolled: %w", input.NodeID, ErrConflict)
	}
	if _, found := findNodeRevocation(repository.state.NodeRevocations, input.NodeID); found {
		return EnrollmentToken{}, fmt.Errorf("node %q is revoked: %w", input.NodeID, ErrRevoked)
	}
	now := repository.now()
	next := cloneState(repository.state)
	token, err := repository.createEnrollmentTokenLocked(&next, input, now)
	if err != nil {
		return EnrollmentToken{}, err
	}
	node, nodeIndex, found := findNode(next.Nodes, input.NodeID)
	kind := NodeEventEnrollmentReissued
	if !found {
		if len(next.Nodes) >= maxNodeRecords {
			return EnrollmentToken{}, fmt.Errorf("node record limit reached: %w", ErrConflict)
		}
		node = NodeRecord{
			NodeID:    input.NodeID,
			Metadata:  NodeMetadata{DisplayName: input.NodeID, Group: "default"},
			Lifecycle: NodeLifecycleEnrolling, Version: 1, CreatedAt: now, UpdatedAt: now,
		}
		next.Nodes = append(next.Nodes, node)
		kind = NodeEventEnrollmentCreated
	} else {
		if node.Lifecycle != NodeLifecycleEnrolling {
			return EnrollmentToken{}, fmt.Errorf("node %q is not awaiting enrollment: %w", input.NodeID, ErrConflict)
		}
		node.Version++
		node.UpdatedAt = now
		next.Nodes[nodeIndex] = node
	}
	if err := appendNodeEvent(&next, NodeLifecycleEvent{
		EventID: "token:" + token.ID, NodeID: input.NodeID, Kind: kind,
		Actor: "command-line", Reason: "enrollment token issued",
		NodeVersion: node.Version, CreatedAt: now,
	}); err != nil {
		return EnrollmentToken{}, err
	}
	if err := repository.commitLocked(next); err != nil {
		return EnrollmentToken{}, err
	}
	return token, nil
}

// Enroll validates a token before acquiring issuer material, then issues the
// leaf, consumes the token, and commits its current-generation pointer in one
// atomic repository mutation. The loader is invoked at most once and only for
// a token that remains eligible while the repository lock is held.
func (repository *FileRepository) Enroll(
	ctx context.Context,
	loadAuthority AuthorityLoader,
	request EnrollmentRequest,
) (CredentialRecord, error) {
	if loadAuthority == nil {
		return CredentialRecord{}, fmt.Errorf("authority loader is nil: %w", ErrInvalid)
	}
	if err := contextError(ctx); err != nil {
		return CredentialRecord{}, err
	}
	if err := validateIdentifier("node ID", request.NodeID); err != nil {
		return CredentialRecord{}, err
	}
	if err := validateText("audience", request.Audience, maxAudienceBytes, true); err != nil {
		return CredentialRecord{}, err
	}
	tokenID, secretDigest, err := parseEnrollmentToken(request.Token)
	if err != nil {
		return CredentialRecord{}, ErrEnrollmentRejected
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return CredentialRecord{}, err
	}
	if err := contextError(ctx); err != nil {
		return CredentialRecord{}, err
	}
	metadata, tokenIndex, found := findEnrollmentWithIndex(repository.state.EnrollmentTokens, tokenID)
	if !constantTimeEnrollmentMatch(metadata, found, secretDigest, request.NodeID, request.Audience, repository.now()) {
		return CredentialRecord{}, ErrEnrollmentRejected
	}
	if _, _, exists := findCurrent(repository.state.CurrentCredentials, request.NodeID); exists {
		return CredentialRecord{}, ErrEnrollmentRejected
	}
	if _, revoked := findNodeRevocation(repository.state.NodeRevocations, request.NodeID); revoked {
		return CredentialRecord{}, ErrEnrollmentRejected
	}
	node, nodeIndex, found := findNode(repository.state.Nodes, request.NodeID)
	if !found || node.Lifecycle != NodeLifecycleEnrolling {
		return CredentialRecord{}, ErrEnrollmentRejected
	}
	authority, err := loadAuthority()
	if err != nil {
		return CredentialRecord{}, err
	}
	if authority == nil {
		return CredentialRecord{}, fmt.Errorf("authority loader returned nil: %w", ErrInvalid)
	}
	if err := contextError(ctx); err != nil {
		return CredentialRecord{}, err
	}
	if !constantTimeEnrollmentMatch(
		metadata, true, secretDigest, request.NodeID, request.Audience, repository.now(),
	) {
		return CredentialRecord{}, ErrEnrollmentRejected
	}
	bundle, err := authority.Issue(ctx, IssueRequest{
		NodeID: request.NodeID, CSRDER: request.CSRDER, Lifetime: request.Lifetime,
	})
	if err != nil {
		return CredentialRecord{}, err
	}
	if err := contextError(ctx); err != nil {
		return CredentialRecord{}, err
	}
	now := repository.now()
	if !constantTimeEnrollmentMatch(
		metadata, true, secretDigest, request.NodeID, request.Audience, now,
	) {
		return CredentialRecord{}, ErrEnrollmentRejected
	}
	record := CredentialRecord{NodeID: request.NodeID, Bundle: bundle, IssuedAt: now}
	if err := validateCredentialRecord(record); err != nil {
		return CredentialRecord{}, err
	}
	if len(repository.state.Credentials) >= maxCredentialRecords || credentialExists(repository.state.Credentials, bundle) {
		return CredentialRecord{}, fmt.Errorf("credential generation conflicts with repository state: %w", ErrConflict)
	}
	next := cloneState(repository.state)
	consumedAt := now
	next.EnrollmentTokens[tokenIndex].ConsumedAt = &consumedAt
	next.Credentials = append(next.Credentials, record)
	next.CurrentCredentials = append(next.CurrentCredentials, currentCredential{
		NodeID: request.NodeID, GenerationID: bundle.GenerationID,
	})
	node.Lifecycle = NodeLifecycleReady
	node.Version++
	node.UpdatedAt = now
	next.Nodes[nodeIndex] = node
	if err := appendNodeEvent(&next, NodeLifecycleEvent{
		EventID: "enroll:" + bundle.GenerationID, NodeID: request.NodeID, Kind: NodeEventEnrolled,
		Actor: "node:" + request.NodeID, Reason: "one-time enrollment credential redeemed",
		NodeVersion: node.Version, CreatedAt: now,
	}); err != nil {
		return CredentialRecord{}, err
	}
	if err := repository.commitLocked(next); err != nil {
		return CredentialRecord{}, err
	}
	return record, nil
}

// RotateCredential issues and atomically makes current a replacement
// generation while retaining prior generations for overlap and audit.
func (repository *FileRepository) RotateCredential(
	ctx context.Context,
	authority *Authority,
	request RotationRequest,
) (CredentialRecord, error) {
	if authority == nil {
		return CredentialRecord{}, fmt.Errorf("authority is nil: %w", ErrInvalid)
	}
	if err := contextError(ctx); err != nil {
		return CredentialRecord{}, err
	}
	if err := validateIdentifier("node ID", request.NodeID); err != nil {
		return CredentialRecord{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return CredentialRecord{}, err
	}
	current, currentIndex, found := findCurrent(repository.state.CurrentCredentials, request.NodeID)
	if !found {
		return CredentialRecord{}, ErrNotFound
	}
	if _, revoked := findNodeRevocation(repository.state.NodeRevocations, request.NodeID); revoked {
		return CredentialRecord{}, ErrRevoked
	}
	currentRecord, _, found := findCredential(repository.state.Credentials, request.NodeID, current.GenerationID)
	if !found {
		return CredentialRecord{}, fmt.Errorf("current credential is missing: %w", ErrCorrupt)
	}
	if credentialIsRevoked(repository.state.CredentialRevocations, currentRecord.Bundle) {
		return CredentialRecord{}, ErrRevoked
	}
	if err := contextError(ctx); err != nil {
		return CredentialRecord{}, err
	}
	bundle, err := authority.Issue(ctx, IssueRequest{
		NodeID: request.NodeID, CSRDER: request.CSRDER, Lifetime: request.Lifetime,
	})
	if err != nil {
		return CredentialRecord{}, err
	}
	record := CredentialRecord{NodeID: request.NodeID, Bundle: bundle, IssuedAt: repository.now()}
	if err := validateCredentialRecord(record); err != nil {
		return CredentialRecord{}, err
	}
	if len(repository.state.Credentials) >= maxCredentialRecords || credentialExists(repository.state.Credentials, bundle) {
		return CredentialRecord{}, fmt.Errorf("credential generation conflicts with repository state: %w", ErrConflict)
	}
	next := cloneState(repository.state)
	next.Credentials = append(next.Credentials, record)
	next.CurrentCredentials[currentIndex].GenerationID = bundle.GenerationID
	if err := repository.commitLocked(next); err != nil {
		return CredentialRecord{}, err
	}
	return record, nil
}

// CurrentCredential returns the node's atomically selected generation.
func (repository *FileRepository) CurrentCredential(ctx context.Context, nodeID string) (CredentialRecord, error) {
	if err := contextError(ctx); err != nil {
		return CredentialRecord{}, err
	}
	if err := validateIdentifier("node ID", nodeID); err != nil {
		return CredentialRecord{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return CredentialRecord{}, err
	}
	current, _, found := findCurrent(repository.state.CurrentCredentials, nodeID)
	if !found {
		return CredentialRecord{}, ErrNotFound
	}
	record, _, found := findCredential(repository.state.Credentials, nodeID, current.GenerationID)
	if !found {
		return CredentialRecord{}, fmt.Errorf("current credential is missing: %w", ErrCorrupt)
	}
	return record, nil
}

// CredentialByGeneration returns one immutable historical node generation.
func (repository *FileRepository) CredentialByGeneration(
	ctx context.Context,
	nodeID string,
	generationID string,
) (CredentialRecord, error) {
	if err := contextError(ctx); err != nil {
		return CredentialRecord{}, err
	}
	if err := validateIdentifier("node ID", nodeID); err != nil {
		return CredentialRecord{}, err
	}
	if err := validateGenerationID(generationID); err != nil {
		return CredentialRecord{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return CredentialRecord{}, err
	}
	record, _, found := findCredential(repository.state.Credentials, nodeID, generationID)
	if !found {
		return CredentialRecord{}, ErrNotFound
	}
	return record, nil
}

// RevokeCredential durably indexes one generation by issuer/serial and leaf
// fingerprint. Repeating the same revocation is idempotent.
func (repository *FileRepository) RevokeCredential(
	ctx context.Context,
	input CredentialRevocationInput,
) (CredentialRevocation, error) {
	if err := contextError(ctx); err != nil {
		return CredentialRevocation{}, err
	}
	if err := validateIdentifier("node ID", input.NodeID); err != nil {
		return CredentialRevocation{}, err
	}
	if err := validateGenerationID(input.GenerationID); err != nil {
		return CredentialRevocation{}, err
	}
	if err := validateText("revocation reason", input.Reason, maxReasonBytes, true); err != nil {
		return CredentialRevocation{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return CredentialRevocation{}, err
	}
	record, _, found := findCredential(repository.state.Credentials, input.NodeID, input.GenerationID)
	if !found {
		return CredentialRevocation{}, ErrNotFound
	}
	if existing, found := findCredentialRevocationByLeaf(
		repository.state.CredentialRevocations,
		record.Bundle.LeafFingerprint,
	); found {
		if existing.Reason != input.Reason {
			return CredentialRevocation{}, fmt.Errorf("credential was revoked with another reason: %w", ErrConflict)
		}
		return existing, nil
	}
	if len(repository.state.CredentialRevocations) >= maxRevocationRecords {
		return CredentialRevocation{}, fmt.Errorf("credential revocation limit reached: %w", ErrConflict)
	}
	revocation := CredentialRevocation{
		NodeID: input.NodeID, GenerationID: input.GenerationID,
		IssuerFingerprint: record.Bundle.IssuerFingerprint,
		Serial:            record.Bundle.Serial, LeafFingerprint: record.Bundle.LeafFingerprint,
		Reason: input.Reason, RevokedAt: repository.now(),
	}
	next := cloneState(repository.state)
	next.CredentialRevocations = append(next.CredentialRevocations, revocation)
	if err := repository.commitLocked(next); err != nil {
		return CredentialRevocation{}, err
	}
	return revocation, nil
}

// RevokeNode durably revokes all present and future credentials for a node.
func (repository *FileRepository) RevokeNode(ctx context.Context, input NodeRevocationInput) (NodeRevocation, error) {
	if err := contextError(ctx); err != nil {
		return NodeRevocation{}, err
	}
	if err := validateIdentifier("node ID", input.NodeID); err != nil {
		return NodeRevocation{}, err
	}
	if err := validateText("revocation reason", input.Reason, maxReasonBytes, true); err != nil {
		return NodeRevocation{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return NodeRevocation{}, err
	}
	if _, _, found := findCurrent(repository.state.CurrentCredentials, input.NodeID); !found {
		return NodeRevocation{}, ErrNotFound
	}
	node, nodeIndex, found := findNode(repository.state.Nodes, input.NodeID)
	if !found {
		return NodeRevocation{}, fmt.Errorf("enrolled node lifecycle record is missing: %w", ErrCorrupt)
	}
	if existing, found := findNodeRevocation(repository.state.NodeRevocations, input.NodeID); found {
		if existing.Reason != input.Reason {
			return NodeRevocation{}, fmt.Errorf("node was revoked with another reason: %w", ErrConflict)
		}
		if node.Lifecycle != NodeLifecycleRevoked {
			return NodeRevocation{}, fmt.Errorf("node revocation lifecycle is inconsistent: %w", ErrCorrupt)
		}
		return existing, nil
	}
	if len(repository.state.NodeRevocations) >= maxRevocationRecords {
		return NodeRevocation{}, fmt.Errorf("node revocation limit reached: %w", ErrConflict)
	}
	now := repository.now()
	revocation := NodeRevocation{NodeID: input.NodeID, Reason: input.Reason, RevokedAt: now}
	next := cloneState(repository.state)
	next.NodeRevocations = append(next.NodeRevocations, revocation)
	node.Lifecycle = NodeLifecycleRevoked
	node.Version++
	node.UpdatedAt = now
	node.RevokedAt = timePointer(now)
	next.Nodes[nodeIndex] = node
	eventID, err := randomIdentifier(repository.random, "revoke_", 16)
	if err != nil {
		return NodeRevocation{}, err
	}
	if err := appendNodeEvent(&next, NodeLifecycleEvent{
		EventID: eventID, NodeID: input.NodeID, Kind: NodeEventRevoked,
		Actor: "command-line", Reason: input.Reason, NodeVersion: node.Version, CreatedAt: now,
	}); err != nil {
		return NodeRevocation{}, err
	}
	if err := repository.commitLocked(next); err != nil {
		return NodeRevocation{}, err
	}
	return revocation, nil
}

// RevocationByIssuerSerial queries the primary X.509 revocation key.
func (repository *FileRepository) RevocationByIssuerSerial(
	ctx context.Context,
	issuerFingerprint string,
	serial string,
) (CredentialRevocation, error) {
	if err := contextError(ctx); err != nil {
		return CredentialRevocation{}, err
	}
	if err := validateFingerprint("issuer fingerprint", issuerFingerprint); err != nil {
		return CredentialRevocation{}, err
	}
	if err := validateSerial(serial); err != nil {
		return CredentialRevocation{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return CredentialRevocation{}, err
	}
	result, found := findCredentialRevocationByIssuerSerial(
		repository.state.CredentialRevocations,
		issuerFingerprint,
		serial,
	)
	if !found {
		return CredentialRevocation{}, ErrNotFound
	}
	return result, nil
}

// RevocationByLeafFingerprint queries the independent leaf digest index.
func (repository *FileRepository) RevocationByLeafFingerprint(
	ctx context.Context,
	leafFingerprint string,
) (CredentialRevocation, error) {
	if err := contextError(ctx); err != nil {
		return CredentialRevocation{}, err
	}
	if err := validateFingerprint("leaf fingerprint", leafFingerprint); err != nil {
		return CredentialRevocation{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return CredentialRevocation{}, err
	}
	result, found := findCredentialRevocationByLeaf(repository.state.CredentialRevocations, leafFingerprint)
	if !found {
		return CredentialRevocation{}, ErrNotFound
	}
	return result, nil
}

// NodeRevocation returns one whole-node revocation record.
func (repository *FileRepository) NodeRevocation(ctx context.Context, nodeID string) (NodeRevocation, error) {
	if err := contextError(ctx); err != nil {
		return NodeRevocation{}, err
	}
	if err := validateIdentifier("node ID", nodeID); err != nil {
		return NodeRevocation{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return NodeRevocation{}, err
	}
	result, found := findNodeRevocation(repository.state.NodeRevocations, nodeID)
	if !found {
		return NodeRevocation{}, ErrNotFound
	}
	return result, nil
}

// RevocationStatus performs one consistent dynamic-verifier query across both
// credential indexes and the whole-node revocation set.
func (repository *FileRepository) RevocationStatus(
	ctx context.Context,
	query RevocationStatusQuery,
) (RevocationStatus, error) {
	if err := contextError(ctx); err != nil {
		return RevocationStatus{}, err
	}
	if err := validateIdentifier("node ID", query.NodeID); err != nil {
		return RevocationStatus{}, err
	}
	if err := validateFingerprint("issuer fingerprint", query.IssuerFingerprint); err != nil {
		return RevocationStatus{}, err
	}
	if err := validateSerial(query.Serial); err != nil {
		return RevocationStatus{}, err
	}
	if err := validateFingerprint("leaf fingerprint", query.LeafFingerprint); err != nil {
		return RevocationStatus{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := repository.ensureOpenLocked(); err != nil {
		return RevocationStatus{}, err
	}
	byStoredSerial, storedSerialFound := findCredentialByIssuerSerial(
		repository.state.Credentials,
		query.IssuerFingerprint,
		query.Serial,
	)
	byStoredLeaf, storedLeafFound := findCredentialByLeaf(
		repository.state.Credentials,
		query.LeafFingerprint,
	)
	if !storedSerialFound && !storedLeafFound {
		return RevocationStatus{}, ErrNotFound
	}
	if storedSerialFound != storedLeafFound || byStoredSerial != byStoredLeaf || byStoredSerial.NodeID != query.NodeID {
		return RevocationStatus{}, fmt.Errorf("stored credential indexes disagree for supplied identity: %w", ErrInvalid)
	}
	status := RevocationStatus{}
	if node, found := findNodeRevocation(repository.state.NodeRevocations, query.NodeID); found {
		copy := node
		status.NodeRevocation = &copy
		status.Revoked = true
	}
	bySerial, serialFound := findCredentialRevocationByIssuerSerial(
		repository.state.CredentialRevocations,
		query.IssuerFingerprint,
		query.Serial,
	)
	byLeaf, leafFound := findCredentialRevocationByLeaf(
		repository.state.CredentialRevocations,
		query.LeafFingerprint,
	)
	if serialFound != leafFound || serialFound && bySerial != byLeaf {
		return RevocationStatus{}, fmt.Errorf("revocation indexes disagree for supplied credential: %w", ErrInvalid)
	}
	if serialFound {
		if bySerial.NodeID != query.NodeID {
			return RevocationStatus{}, fmt.Errorf("revoked credential belongs to another node: %w", ErrInvalid)
		}
		copy := bySerial
		status.CredentialRevocation = &copy
		status.Revoked = true
	}
	return status, nil
}

// Close releases the exclusive process lock. It is safe to call repeatedly.
func (repository *FileRepository) Close() error {
	if repository == nil {
		return nil
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.closed {
		return nil
	}
	repository.closed = true
	return repository.lock.release()
}

func (repository *FileRepository) loadState() (persistedState, error) {
	data, err := readPrivateFile(repository.statePath(), maxStateBytes)
	if err != nil {
		return persistedState{}, err
	}
	var envelope stateEnvelope
	if err := strictJSON(data, &envelope); err != nil {
		return persistedState{}, err
	}
	stateBytes, err := json.Marshal(envelope.State)
	if err != nil {
		return persistedState{}, fmt.Errorf("remarshal identity state: %w", err)
	}
	digest := sha256.Sum256(stateBytes)
	if !hmac.Equal([]byte(envelope.IntegritySHA256), []byte(hex.EncodeToString(digest[:]))) {
		return persistedState{}, fmt.Errorf("identity state checksum mismatch: %w", ErrCorrupt)
	}
	return envelope.State, nil
}

func (repository *FileRepository) writeState(state persistedState) error {
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal identity state: %w", err)
	}
	digest := sha256.Sum256(stateBytes)
	envelope := stateEnvelope{IntegritySHA256: hex.EncodeToString(digest[:]), State: state}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity envelope: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxStateBytes {
		return fmt.Errorf("identity state exceeds %d bytes: %w", maxStateBytes, ErrConflict)
	}
	return writeFileAtomicPrivate(repository.statePath(), data)
}

func (repository *FileRepository) commitLocked(next persistedState) error {
	if repository.state.Generation == math.MaxUint64 {
		return fmt.Errorf("identity generation exhausted: %w", ErrConflict)
	}
	next.SchemaVersion = repositorySchemaVersion
	next.Generation = repository.state.Generation + 1
	if err := validateState(next); err != nil {
		return err
	}
	if err := repository.writeState(next); err != nil {
		return err
	}
	repository.state = next
	return nil
}

func (repository *FileRepository) ensureOpenLocked() error {
	if repository.closed {
		return ErrClosed
	}
	return nil
}

func (repository *FileRepository) statePath() string {
	return filepath.Join(repository.root, stateDirectoryName, stateFileName)
}

func (repository *FileRepository) now() time.Time {
	return repository.clock().UTC()
}

func parseEnrollmentToken(value string) (string, [sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if len(value) != enrollmentTokenBytes {
		return "", digest, ErrEnrollmentRejected
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != "bv1" {
		return "", digest, ErrEnrollmentRejected
	}
	idBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(idBytes) != 16 || base64.RawURLEncoding.EncodeToString(idBytes) != parts[1] {
		return "", digest, ErrEnrollmentRejected
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != parts[2] {
		return "", digest, ErrEnrollmentRejected
	}
	digest = sha256.Sum256(secret)
	clear(secret)
	return parts[1], digest, nil
}

func constantTimeEnrollmentMatch(
	metadata enrollmentMetadata,
	found bool,
	secretDigest [sha256.Size]byte,
	nodeID string,
	audience string,
	now time.Time,
) bool {
	storedDigest := make([]byte, sha256.Size)
	if decoded, err := hex.DecodeString(metadata.SecretSHA256); err == nil && len(decoded) == sha256.Size {
		copy(storedDigest, decoded)
	}
	secretMatches := hmac.Equal(storedDigest, secretDigest[:])
	nodeDigest := sha256.Sum256([]byte(nodeID))
	storedNodeDigest := sha256.Sum256([]byte(metadata.NodeID))
	audienceDigest := sha256.Sum256([]byte(audience))
	storedAudienceDigest := sha256.Sum256([]byte(metadata.Audience))
	return found && secretMatches && hmac.Equal(nodeDigest[:], storedNodeDigest[:]) &&
		hmac.Equal(audienceDigest[:], storedAudienceDigest[:]) &&
		metadata.ConsumedAt == nil && now.Before(metadata.ExpiresAt)
}

func randomIdentifier(reader io.Reader, prefix string, byteCount int) (string, error) {
	value := make([]byte, byteCount)
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", fmt.Errorf("generate random identifier: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(value), nil
}

func cloneState(state persistedState) persistedState {
	next := persistedState{
		SchemaVersion:         state.SchemaVersion,
		Generation:            state.Generation,
		EnrollmentTokens:      append([]enrollmentMetadata(nil), state.EnrollmentTokens...),
		Credentials:           append([]CredentialRecord(nil), state.Credentials...),
		CurrentCredentials:    append([]currentCredential(nil), state.CurrentCredentials...),
		CredentialRevocations: append([]CredentialRevocation(nil), state.CredentialRevocations...),
		NodeRevocations:       append([]NodeRevocation(nil), state.NodeRevocations...),
		Nodes:                 append([]NodeRecord(nil), state.Nodes...),
		NodeEvents:            append([]NodeLifecycleEvent(nil), state.NodeEvents...),
	}
	for index := range next.Nodes {
		next.Nodes[index].Metadata.Labels = cloneLabels(next.Nodes[index].Metadata.Labels)
	}
	return next
}

func pruneEnrollmentTokens(tokens []enrollmentMetadata, now time.Time) []enrollmentMetadata {
	kept := make([]enrollmentMetadata, 0, len(tokens))
	for _, token := range tokens {
		if token.ConsumedAt == nil && now.Before(token.ExpiresAt) {
			kept = append(kept, token)
		}
	}
	return kept
}

func findEnrollment(tokens []enrollmentMetadata, id string) (enrollmentMetadata, bool) {
	result, _, found := findEnrollmentWithIndex(tokens, id)
	return result, found
}

func findEnrollmentWithIndex(tokens []enrollmentMetadata, id string) (enrollmentMetadata, int, bool) {
	for index, token := range tokens {
		if token.ID == id {
			return token, index, true
		}
	}
	return enrollmentMetadata{}, -1, false
}

func findCurrent(records []currentCredential, nodeID string) (currentCredential, int, bool) {
	for index, record := range records {
		if record.NodeID == nodeID {
			return record, index, true
		}
	}
	return currentCredential{}, -1, false
}

func findCredential(records []CredentialRecord, nodeID, generationID string) (CredentialRecord, int, bool) {
	for index, record := range records {
		if record.NodeID == nodeID && record.Bundle.GenerationID == generationID {
			return record, index, true
		}
	}
	return CredentialRecord{}, -1, false
}

func findCredentialByIssuerSerial(
	records []CredentialRecord,
	issuerFingerprint string,
	serial string,
) (CredentialRecord, bool) {
	for _, record := range records {
		if record.Bundle.IssuerFingerprint == issuerFingerprint && record.Bundle.Serial == serial {
			return record, true
		}
	}
	return CredentialRecord{}, false
}

func findCredentialByLeaf(records []CredentialRecord, leafFingerprint string) (CredentialRecord, bool) {
	for _, record := range records {
		if record.Bundle.LeafFingerprint == leafFingerprint {
			return record, true
		}
	}
	return CredentialRecord{}, false
}

func findCredentialRevocationByIssuerSerial(
	records []CredentialRevocation,
	issuerFingerprint string,
	serial string,
) (CredentialRevocation, bool) {
	for _, record := range records {
		if record.IssuerFingerprint == issuerFingerprint && record.Serial == serial {
			return record, true
		}
	}
	return CredentialRevocation{}, false
}

func findCredentialRevocationByLeaf(
	records []CredentialRevocation,
	leafFingerprint string,
) (CredentialRevocation, bool) {
	for _, record := range records {
		if record.LeafFingerprint == leafFingerprint {
			return record, true
		}
	}
	return CredentialRevocation{}, false
}

func findNodeRevocation(records []NodeRevocation, nodeID string) (NodeRevocation, bool) {
	for _, record := range records {
		if record.NodeID == nodeID {
			return record, true
		}
	}
	return NodeRevocation{}, false
}

func credentialExists(records []CredentialRecord, bundle CredentialBundle) bool {
	for _, record := range records {
		if record.Bundle.GenerationID == bundle.GenerationID ||
			record.Bundle.LeafFingerprint == bundle.LeafFingerprint ||
			record.Bundle.IssuerFingerprint == bundle.IssuerFingerprint && record.Bundle.Serial == bundle.Serial {
			return true
		}
	}
	return false
}

func credentialIsRevoked(records []CredentialRevocation, bundle CredentialBundle) bool {
	_, found := findCredentialRevocationByLeaf(records, bundle.LeafFingerprint)
	return found
}

func validateState(state persistedState) error {
	if state.SchemaVersion != repositorySchemaVersion || state.Generation == 0 {
		return fmt.Errorf("unsupported identity state header: %w", ErrCorrupt)
	}
	if len(state.EnrollmentTokens) > maxActiveTokens || len(state.Credentials) > maxCredentialRecords ||
		len(state.CredentialRevocations) > maxRevocationRecords || len(state.NodeRevocations) > maxRevocationRecords ||
		len(state.Nodes) > maxNodeRecords || len(state.NodeEvents) > maxNodeEvents {
		return fmt.Errorf("identity state exceeds record limits: %w", ErrCorrupt)
	}
	nodes := make(map[string]NodeRecord, len(state.Nodes))
	for _, node := range state.Nodes {
		if err := validateNodeRecord(node); err != nil {
			return fmt.Errorf("invalid stored node: %w: %v", ErrCorrupt, err)
		}
		if _, duplicate := nodes[node.NodeID]; duplicate {
			return fmt.Errorf("duplicate node record: %w", ErrCorrupt)
		}
		nodes[node.NodeID] = node
	}
	for _, node := range state.Nodes {
		if node.ReplacementFor != "" {
			predecessor, exists := nodes[node.ReplacementFor]
			if !exists || predecessor.ReplacedBy != node.NodeID {
				return fmt.Errorf("replacement predecessor link is inconsistent: %w", ErrCorrupt)
			}
		}
		if node.ReplacedBy != "" {
			replacement, exists := nodes[node.ReplacedBy]
			if !exists || replacement.ReplacementFor != node.NodeID {
				return fmt.Errorf("replacement successor link is inconsistent: %w", ErrCorrupt)
			}
		}
	}
	tokenIDs := make(map[string]struct{}, len(state.EnrollmentTokens))
	for _, token := range state.EnrollmentTokens {
		idBytes, err := base64.RawURLEncoding.DecodeString(token.ID)
		secretDigest, digestErr := hex.DecodeString(token.SecretSHA256)
		if err != nil || len(idBytes) != 16 || base64.RawURLEncoding.EncodeToString(idBytes) != token.ID ||
			digestErr != nil || len(secretDigest) != sha256.Size || token.SecretSHA256 != strings.ToLower(token.SecretSHA256) ||
			token.CreatedAt.IsZero() || !token.ExpiresAt.After(token.CreatedAt) {
			return fmt.Errorf("invalid enrollment token metadata: %w", ErrCorrupt)
		}
		if err := validateIdentifier("stored token node ID", token.NodeID); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if err := validateText("stored token audience", token.Audience, maxAudienceBytes, true); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if token.ConsumedAt != nil && (token.ConsumedAt.Before(token.CreatedAt) || token.ConsumedAt.After(token.ExpiresAt)) {
			return fmt.Errorf("invalid enrollment consumption time: %w", ErrCorrupt)
		}
		if _, duplicate := tokenIDs[token.ID]; duplicate {
			return fmt.Errorf("duplicate enrollment token ID: %w", ErrCorrupt)
		}
		node, exists := nodes[token.NodeID]
		if !exists || token.ConsumedAt == nil && node.Lifecycle != NodeLifecycleEnrolling {
			return fmt.Errorf("enrollment token references an ineligible node: %w", ErrCorrupt)
		}
		tokenIDs[token.ID] = struct{}{}
	}

	generations := make(map[string]CredentialRecord, len(state.Credentials))
	leaves := make(map[string]struct{}, len(state.Credentials))
	issuerSerials := make(map[string]struct{}, len(state.Credentials))
	for _, record := range state.Credentials {
		if err := validateCredentialRecord(record); err != nil {
			return fmt.Errorf("invalid stored credential: %w: %v", ErrCorrupt, err)
		}
		if _, duplicate := generations[record.Bundle.GenerationID]; duplicate {
			return fmt.Errorf("duplicate credential generation: %w", ErrCorrupt)
		}
		if _, duplicate := leaves[record.Bundle.LeafFingerprint]; duplicate {
			return fmt.Errorf("duplicate credential leaf fingerprint: %w", ErrCorrupt)
		}
		issuerSerial := record.Bundle.IssuerFingerprint + "\x00" + record.Bundle.Serial
		if _, duplicate := issuerSerials[issuerSerial]; duplicate {
			return fmt.Errorf("duplicate credential issuer and serial: %w", ErrCorrupt)
		}
		generations[record.Bundle.GenerationID] = record
		leaves[record.Bundle.LeafFingerprint] = struct{}{}
		issuerSerials[issuerSerial] = struct{}{}
	}
	currentNodes := make(map[string]struct{}, len(state.CurrentCredentials))
	for _, current := range state.CurrentCredentials {
		if err := validateIdentifier("stored current node ID", current.NodeID); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		record, exists := generations[current.GenerationID]
		if !exists || record.NodeID != current.NodeID {
			return fmt.Errorf("current credential points to a missing or different node generation: %w", ErrCorrupt)
		}
		if _, duplicate := currentNodes[current.NodeID]; duplicate {
			return fmt.Errorf("duplicate current node credential: %w", ErrCorrupt)
		}
		node, exists := nodes[current.NodeID]
		if !exists || node.Lifecycle == NodeLifecycleEnrolling {
			return fmt.Errorf("current credential has no enrolled node lifecycle: %w", ErrCorrupt)
		}
		currentNodes[current.NodeID] = struct{}{}
	}
	revokedLeaves := make(map[string]struct{}, len(state.CredentialRevocations))
	revokedIssuerSerials := make(map[string]struct{}, len(state.CredentialRevocations))
	for _, revocation := range state.CredentialRevocations {
		record, exists := generations[revocation.GenerationID]
		if !exists || record.NodeID != revocation.NodeID ||
			record.Bundle.IssuerFingerprint != revocation.IssuerFingerprint ||
			record.Bundle.Serial != revocation.Serial || record.Bundle.LeafFingerprint != revocation.LeafFingerprint ||
			revocation.RevokedAt.IsZero() {
			return fmt.Errorf("credential revocation does not match its generation: %w", ErrCorrupt)
		}
		if err := validateText("stored credential revocation reason", revocation.Reason, maxReasonBytes, true); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		issuerSerial := revocation.IssuerFingerprint + "\x00" + revocation.Serial
		if _, duplicate := revokedLeaves[revocation.LeafFingerprint]; duplicate {
			return fmt.Errorf("duplicate leaf revocation: %w", ErrCorrupt)
		}
		if _, duplicate := revokedIssuerSerials[issuerSerial]; duplicate {
			return fmt.Errorf("duplicate issuer and serial revocation: %w", ErrCorrupt)
		}
		revokedLeaves[revocation.LeafFingerprint] = struct{}{}
		revokedIssuerSerials[issuerSerial] = struct{}{}
	}
	revokedNodes := make(map[string]struct{}, len(state.NodeRevocations))
	for _, revocation := range state.NodeRevocations {
		if _, enrolled := currentNodes[revocation.NodeID]; !enrolled || revocation.RevokedAt.IsZero() {
			return fmt.Errorf("node revocation references an unknown node: %w", ErrCorrupt)
		}
		if err := validateText("stored node revocation reason", revocation.Reason, maxReasonBytes, true); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if _, duplicate := revokedNodes[revocation.NodeID]; duplicate {
			return fmt.Errorf("duplicate node revocation: %w", ErrCorrupt)
		}
		if node, exists := nodes[revocation.NodeID]; !exists || node.Lifecycle != NodeLifecycleRevoked ||
			node.RevokedAt == nil || !node.RevokedAt.Equal(revocation.RevokedAt) {
			return fmt.Errorf("node revocation lifecycle is inconsistent: %w", ErrCorrupt)
		}
		revokedNodes[revocation.NodeID] = struct{}{}
	}
	eventIDs := make(map[string]struct{}, len(state.NodeEvents))
	for index, event := range state.NodeEvents {
		if event.Index != uint64(index)+1 || !canonicalNodeEventKind(event.Kind) || event.CreatedAt.IsZero() ||
			event.NodeVersion == 0 {
			return fmt.Errorf("node lifecycle event header is invalid: %w", ErrCorrupt)
		}
		if err := validateIdentifier("node lifecycle event ID", event.EventID); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if err := validateIdentifier("node lifecycle event node ID", event.NodeID); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if event.RequestSHA256 != "" {
			digest, err := hex.DecodeString(event.RequestSHA256)
			if err != nil || len(digest) != sha256.Size || event.RequestSHA256 != strings.ToLower(event.RequestSHA256) {
				return fmt.Errorf("node lifecycle request digest is invalid: %w", ErrCorrupt)
			}
		}
		if err := validateText("node lifecycle event actor", event.Actor, maxNodeActorBytes, true); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if err := validateText("node lifecycle event reason", event.Reason, maxReasonBytes, true); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		node, exists := nodes[event.NodeID]
		if !exists || event.NodeVersion > node.Version || event.CreatedAt.Before(node.CreatedAt) ||
			event.CreatedAt.After(node.UpdatedAt) {
			return fmt.Errorf("node lifecycle event does not match its node: %w", ErrCorrupt)
		}
		if event.RelatedNodeID != "" {
			if _, exists := nodes[event.RelatedNodeID]; !exists {
				return fmt.Errorf("node lifecycle event relation is missing: %w", ErrCorrupt)
			}
		}
		if _, duplicate := eventIDs[event.EventID]; duplicate {
			return fmt.Errorf("duplicate node lifecycle event ID: %w", ErrCorrupt)
		}
		eventIDs[event.EventID] = struct{}{}
	}
	return nil
}

func validateNodeRecord(node NodeRecord) error {
	if err := validateIdentifier("stored node ID", node.NodeID); err != nil {
		return err
	}
	if err := validateNodeMetadata(node.Metadata); err != nil {
		return err
	}
	if !validNodeLifecycle(node.Lifecycle) || node.Version == 0 || node.CreatedAt.IsZero() ||
		node.UpdatedAt.IsZero() || node.UpdatedAt.Before(node.CreatedAt) {
		return fmt.Errorf("node lifecycle header is invalid: %w", ErrInvalid)
	}
	for name, value := range map[string]string{
		"replacement predecessor": node.ReplacementFor,
		"replacement successor":   node.ReplacedBy,
	} {
		if value != "" {
			if err := validateIdentifier(name, value); err != nil || value == node.NodeID {
				return fmt.Errorf("node replacement link is invalid: %w", ErrInvalid)
			}
		}
	}
	validTimestamp := func(value *time.Time) bool {
		return value == nil || !value.IsZero() && !value.Before(node.CreatedAt) && !value.After(node.UpdatedAt)
	}
	if !validTimestamp(node.DrainRequestedAt) || !validTimestamp(node.RetiredAt) || !validTimestamp(node.RevokedAt) {
		return fmt.Errorf("node lifecycle timestamp is invalid: %w", ErrInvalid)
	}
	switch node.Lifecycle {
	case NodeLifecycleEnrolling, NodeLifecycleReady:
		if node.DrainRequestedAt != nil || node.RetiredAt != nil || node.RevokedAt != nil {
			return fmt.Errorf("active node has a terminal timestamp: %w", ErrInvalid)
		}
	case NodeLifecycleDraining:
		if node.DrainRequestedAt == nil || node.RetiredAt != nil || node.RevokedAt != nil {
			return fmt.Errorf("draining node timestamps are inconsistent: %w", ErrInvalid)
		}
	case NodeLifecycleRetired:
		if node.DrainRequestedAt == nil || node.RetiredAt == nil || node.RevokedAt != nil {
			return fmt.Errorf("retired node timestamps are inconsistent: %w", ErrInvalid)
		}
	case NodeLifecycleRevoked:
		if node.RevokedAt == nil || node.RetiredAt != nil {
			return fmt.Errorf("revoked node timestamps are inconsistent: %w", ErrInvalid)
		}
	}
	return nil
}

func validateCredentialRecord(record CredentialRecord) error {
	if err := validateIdentifier("credential node ID", record.NodeID); err != nil {
		return err
	}
	bundle := record.Bundle
	if err := validateGenerationID(bundle.GenerationID); err != nil {
		return err
	}
	if err := validateFingerprint("leaf fingerprint", bundle.LeafFingerprint); err != nil {
		return err
	}
	if err := validateFingerprint("issuer fingerprint", bundle.IssuerFingerprint); err != nil {
		return err
	}
	if err := validateSerial(bundle.Serial); err != nil {
		return err
	}
	if record.IssuedAt.IsZero() || bundle.NotBefore.IsZero() || record.IssuedAt.Before(bundle.NotBefore) ||
		!record.IssuedAt.Before(bundle.NotAfter) || !bundle.NotAfter.After(bundle.NotBefore) ||
		!bundle.RenewAfter.Equal(bundle.NotBefore.Add(bundle.NotAfter.Sub(bundle.NotBefore)*2/3)) {
		return fmt.Errorf("credential timestamps are invalid: %w", ErrInvalid)
	}
	chainBlocks, err := strictPEMBlocks([]byte(bundle.ChainPEM), "CERTIFICATE")
	if err != nil || len(chainBlocks) != 2 {
		return fmt.Errorf("credential chain must contain leaf and issuer: %w", joinInvalid(err))
	}
	leaf, err := x509.ParseCertificate(chainBlocks[0].Bytes)
	if err != nil {
		return fmt.Errorf("parse credential leaf: %w", err)
	}
	issuer, err := x509.ParseCertificate(chainBlocks[1].Bytes)
	if err != nil {
		return fmt.Errorf("parse credential issuer: %w", err)
	}
	if fingerprint(leaf.Raw) != bundle.LeafFingerprint || fingerprint(issuer.Raw) != bundle.IssuerFingerprint ||
		leaf.SerialNumber.Text(16) != bundle.Serial || !leaf.NotBefore.Equal(bundle.NotBefore) ||
		!leaf.NotAfter.Equal(bundle.NotAfter) {
		return fmt.Errorf("credential metadata disagrees with certificate bytes: %w", ErrInvalid)
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("credential leaf key is not ECDSA P-256: %w", ErrInvalid)
	}
	if err := validateIssuingCertificate(issuer, record.IssuedAt); err != nil {
		return err
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].Scheme != "spiffe" || leaf.URIs[0].Host == "" ||
		leaf.URIs[0].RawQuery != "" || leaf.URIs[0].Fragment != "" ||
		!strings.HasSuffix(leaf.URIs[0].Path, "/"+record.NodeID) {
		return fmt.Errorf("credential does not contain exactly one matching SPIFFE node identity: %w", ErrInvalid)
	}
	if err := validateIssuedLeaf(leaf, record.NodeID, leaf.URIs[0], issuer); err != nil {
		return err
	}
	trustBlocks, err := strictPEMBlocks([]byte(bundle.TrustBundlePEM), "CERTIFICATE")
	if err != nil {
		return fmt.Errorf("parse credential trust bundle: %w", err)
	}
	roots := x509.NewCertPool()
	for _, block := range trustBlocks {
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return fmt.Errorf("parse credential trust certificate: %w", parseErr)
		}
		if err := validateTrustCertificate(certificate, record.IssuedAt); err != nil {
			return err
		}
		roots.AddCert(certificate)
	}
	if _, err := issuer.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: record.IssuedAt, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("credential issuer is not anchored by retained trust: %w", err)
	}
	return nil
}
