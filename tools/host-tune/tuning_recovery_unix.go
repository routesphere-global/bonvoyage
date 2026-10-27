//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type tuningRecoveryBackend interface {
	tuningBackend
	LockRecovery(context.Context, tuningTransaction) (func(), error)
}
type tuningRecoverySource struct {
	directory   string
	sha256      string
	transaction tuningTransaction
	attempted   int
	purpose     string
}
type tuningRecoveryReview struct {
	Scope               string          `json:"scope"`
	NICVerification     string          `json:"nic_irq_verification"`
	Purpose             string          `json:"purpose"`
	JournalSHA256       string          `json:"journal_sha256"`
	InputManifestSHA256 string          `json:"input_manifest_sha256"`
	IntentSHA256        string          `json:"intent_sha256"`
	Identity            tuningIdentity  `json:"identity"`
	Current             []tuningValue   `json:"current"`
	RestoreIndices      []int           `json:"restore_indices"`
	Runtime             json.RawMessage `json:"runtime,omitempty"`
	ApprovalSHA256      string          `json:"approval_sha256"`
}

func loadTuningRecovery(directory, anchor string, inputs verifiedTuningInputs) (tuningRecoverySource, error) {
	return loadTuningRestorationSource(directory, anchor, inputs, "interrupted")
}

func loadTuningRollback(directory, anchor string, inputs verifiedTuningInputs) (tuningRecoverySource, error) {
	return loadTuningRestorationSource(directory, anchor, inputs, "rollback")
}

func reloadTuningRestoration(source tuningRecoverySource, inputs verifiedTuningInputs) (tuningRecoverySource, error) {
	return loadTuningRestorationSource(source.directory, source.sha256, inputs, source.purpose)
}

func loadTuningRestorationSource(directory, anchor string, inputs verifiedTuningInputs, purpose string) (tuningRecoverySource, error) {
	rejected := tuningRecoverySource{}
	if purpose != "interrupted" && purpose != "rollback" {
		return rejected, errors.New("unsupported restoration purpose")
	}
	if !validSHA256(anchor) {
		return rejected, errors.New("reviewed journal digest required")
	}
	files, err := readPrivateTuningDirectory(directory, 32)
	if err != nil {
		return rejected, err
	}
	if digest(tuningFileManifest(files)) != anchor {
		return rejected, errors.New("journal snapshot changed")
	}
	source := tuningRecoverySource{directory: directory, sha256: anchor, purpose: purpose}
	previous := ""
	rollback := false
	lastRollback := 3
	verified := false
	terminal := ""
	for i := 1; i <= len(files); i++ {
		data, ok := files[fmt.Sprintf("%06d.json", i)]
		if !ok {
			return rejected, errors.New("journal sequence gap")
		}
		var envelope tuningJournalEnvelope
		var entry tuningJournalEntry
		if err := decodeTuningJSON(data, &envelope); err != nil {
			return rejected, err
		}
		if digest(envelope.Entry) != envelope.SHA256 {
			return rejected, errors.New("journal entry checksum mismatch")
		}
		if err := decodeTuningJSON(envelope.Entry, &entry); err != nil {
			return rejected, err
		}
		if entry.Sequence != i || entry.PreviousSHA256 != previous || terminal != "" {
			return rejected, errors.New("invalid journal ordering")
		}
		previous = envelope.SHA256
		if i == 1 {
			if entry.Kind != "prepared" {
				return rejected, errors.New("recovery requires original prepared journal")
			}
			if err := decodeTuningJSON(entry.Data, &source.transaction); err != nil {
				return rejected, err
			}
			if err := validateRetainedTransaction(inputs, source.transaction); err != nil {
				return rejected, err
			}
			continue
		}
		switch entry.Kind {
		case "write-intent":
			var index int
			if err := decodeTuningJSON(entry.Data, &index); err != nil {
				return rejected, err
			}
			if rollback || verified || index != source.attempted || index >= 3 {
				return rejected, errors.New("invalid write intent")
			}
			source.attempted++
		case "rollback-intent":
			var index int
			if err := decodeTuningJSON(entry.Data, &index); err != nil {
				return rejected, err
			}
			if index < 0 || index >= source.attempted || index >= lastRollback {
				return rejected, errors.New("invalid rollback intent")
			}
			rollback = true
			lastRollback = index
		case "runtime-verified":
			if rollback || verified || source.attempted != 3 {
				return rejected, errors.New("invalid runtime verification order")
			}
			verified = true
		case "applied":
			if rollback || !verified || source.attempted != 3 {
				return rejected, errors.New("invalid applied terminal")
			}
			terminal = entry.Kind
		case "rolled-back", "recovery-required":
			terminal = entry.Kind
		default:
			return rejected, errors.New("unsupported recovery event")
		}
	}
	if purpose == "rollback" {
		if terminal != "applied" {
			return rejected, errors.New("orderly rollback requires a completed applied journal")
		}
	} else if terminal == "applied" || terminal == "rolled-back" {
		return rejected, errors.New("completed attempt is not an interrupted run")
	}
	return source, nil
}

func recoveryDeadline(ctx context.Context) error {
	end, ok := ctx.Deadline()
	if !ok || time.Until(end) <= 0 || time.Until(end) > 10*time.Minute {
		return errors.New("recovery requires a deadline within ten minutes")
	}
	return ctx.Err()
}

func reviewTuningRecoveryLocked(ctx context.Context, inputs verifiedTuningInputs, source tuningRecoverySource,
	backend tuningRecoveryBackend) (tuningRecoveryReview, error) {
	review := tuningRecoveryReview{Purpose: source.purpose, JournalSHA256: source.sha256, InputManifestSHA256: inputs.manifestSHA256,
		IntentSHA256: source.transaction.IntentSHA256, Identity: source.transaction.Identity}
	review.Scope = effectiveTuningScope(source.transaction.Plan.Scope)
	review.NICVerification = tuningNICVerification(source.transaction.Plan.Scope)
	if err := checkTuningIdentity(ctx, backend, source.transaction.Identity); err != nil {
		return review, err
	}
	for i, change := range source.transaction.Changes {
		current, err := backend.Read(ctx, change.Control)
		if err != nil {
			return review, err
		}
		if !validTuningValue(current) {
			return review, errors.New("unsupported current control")
		}
		current.Data = append([]byte(nil), current.Data...)
		review.Current = append(review.Current, current)
		if equalTuningValue(current, change.Before) {
			continue
		}
		if i >= source.attempted || !equalTuningValue(current, change.After) {
			return review, fmt.Errorf("recovery preserves conflicting/unattempted control: %s", change.Control)
		}
		review.RestoreIndices = append([]int{i}, review.RestoreIndices...)
	}
	var err error
	review.Runtime, err = captureTuningRuntime(ctx, backend)
	if err != nil {
		return review, err
	}
	if err = checkTuningIdentity(ctx, backend, source.transaction.Identity); err != nil {
		return review, err
	}
	encoded, err := json.Marshal(review)
	if err != nil {
		return review, err
	}
	review.ApprovalSHA256 = digest(encoded)
	return review, nil
}

// Review is read-only under the host lock. Its digest binds current observations;
// execution acquires a fresh lock and refuses any drift since this review.
func reviewTuningRecovery(ctx context.Context, inputs verifiedTuningInputs, source tuningRecoverySource,
	backend tuningRecoveryBackend) (tuningRecoveryReview, error) {
	if err := recoveryDeadline(ctx); err != nil {
		return tuningRecoveryReview{}, err
	}
	fresh, err := reloadTuningRestoration(source, inputs)
	if err != nil {
		return tuningRecoveryReview{}, err
	}
	unlock, err := backend.LockRecovery(ctx, fresh.transaction)
	if err != nil {
		return tuningRecoveryReview{}, err
	}
	if unlock == nil {
		return tuningRecoveryReview{}, errors.New("recovery lock missing")
	}
	defer unlock()
	// An apply may have completed while we waited for the host lock.
	fresh, err = reloadTuningRestoration(source, inputs)
	if err != nil {
		return tuningRecoveryReview{}, err
	}
	return reviewTuningRecoveryLocked(ctx, inputs, fresh, backend)
}

func recoverTuningTransaction(ctx context.Context, inputs verifiedTuningInputs, source tuningRecoverySource,
	approval string, backend tuningRecoveryBackend, journal tuningJournal) (tuningOutcome, error) {
	rejected := tuningOutcome{Status: "rejected"}
	if err := recoveryDeadline(ctx); err != nil {
		return rejected, err
	}
	if !validSHA256(approval) {
		return rejected, errors.New("explicit recovery approval required")
	}
	fresh, err := reloadTuningRestoration(source, inputs)
	if err != nil {
		return rejected, err
	}
	unlock, err := backend.LockRecovery(ctx, fresh.transaction)
	if err != nil {
		return rejected, err
	}
	if unlock == nil {
		return rejected, errors.New("recovery lock missing")
	}
	defer unlock()
	fresh, err = reloadTuningRestoration(source, inputs)
	if err != nil {
		return rejected, err
	}
	review, err := reviewTuningRecoveryLocked(ctx, inputs, fresh, backend)
	if err != nil {
		return rejected, err
	}
	if review.ApprovalSHA256 != approval {
		return rejected, errors.New("recovery observations changed after approval")
	}
	if err = journal.Record("recovery-prepared", struct {
		Review      tuningRecoveryReview `json:"review"`
		Transaction tuningTransaction    `json:"transaction"`
	}{review, fresh.transaction}); err != nil {
		return rejected, err
	}
	restoreErr := func() error {
		for _, i := range review.RestoreIndices {
			change := fresh.transaction.Changes[i]
			if err := checkTuningIdentity(ctx, backend, fresh.transaction.Identity); err != nil {
				return err
			}
			if err := journal.Record("recovery-write-intent", i); err != nil {
				return err
			}
			if err := backend.Replace(ctx, change.Control, change.After, change.Before); err != nil {
				return err
			}
			current, err := backend.Read(ctx, change.Control)
			if err != nil {
				return err
			}
			if !equalTuningValue(current, change.Before) {
				return errors.New("recovery write did not verify")
			}
		}
		for _, change := range fresh.transaction.Changes {
			current, err := backend.Read(ctx, change.Control)
			if err != nil {
				return err
			}
			if !equalTuningValue(current, change.Before) {
				return errors.New("recovery control drift before activation")
			}
		}
		if err := checkTuningIdentity(ctx, backend, fresh.transaction.Identity); err != nil {
			return err
		}
		if err := backend.VerifyRestored(ctx, fresh.transaction.Changes); err != nil {
			return err
		}
		return checkTuningIdentity(ctx, backend, fresh.transaction.Identity)
	}()
	status := "recovery-restored"
	if restoreErr != nil {
		status = "recovery-required"
	}
	evidence, evidenceErr := captureTuningRuntime(ctx, backend)
	if evidenceErr != nil {
		status = "recovery-required"
		restoreErr = errors.Join(restoreErr, evidenceErr)
	}
	reason := ""
	if restoreErr != nil {
		reason = restoreErr.Error()
	}
	if err = journal.Record(status, struct {
		Reason  string          `json:"reason,omitempty"`
		Runtime json.RawMessage `json:"runtime,omitempty"`
	}{reason, evidence}); err != nil {
		status = "recovery-required"
		restoreErr = errors.Join(restoreErr, err)
	}
	return tuningOutcome{Status: status}, restoreErr
}
