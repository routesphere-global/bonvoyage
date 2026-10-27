package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/identity"
	"github.com/routesphere-global/bonvoyage/control-plane/internal/nodecredentials"
)

func runIssueEnrollmentToken(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) (returnErr error) {
	flags := flag.NewFlagSet("bonvoyage-control-plane issue-enrollment-token", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repositoryRoot := flags.String("identity-repository-root", "", "path to the durable node identity repository")
	nodeID := flags.String("node-id", "", "exact node identity bound to this token")
	audience := flags.String("audience", "", "exact installation audience bound to this token")
	ttl := flags.Duration("ttl", identity.DefaultEnrollmentTTL, "short token lifetime")
	output := flags.String("token-output", "", "new owner-only file that receives the one-time bearer token")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("issue-enrollment-token: unexpected positional arguments: %v", flags.Args())
	}
	if strings.TrimSpace(*repositoryRoot) == "" || strings.TrimSpace(*nodeID) == "" ||
		strings.TrimSpace(*audience) == "" || strings.TrimSpace(*output) == "" ||
		!filepath.IsAbs(*repositoryRoot) || !filepath.IsAbs(*output) {
		return errors.New("issue-enrollment-token: repository, node, audience, and absolute output path are required")
	}
	if err := validateNewPrivateFileDestination(*output); err != nil {
		return fmt.Errorf("issue-enrollment-token: validate token output: %w", err)
	}
	repository, err := identity.OpenFileRepository(*repositoryRoot, identity.FileRepositoryOptions{})
	if err != nil {
		return fmt.Errorf("issue-enrollment-token: open identity repository: %w", err)
	}
	defer func() {
		if err := repository.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("issue-enrollment-token: close identity repository: %w", err))
		}
	}()
	token, err := repository.CreateEnrollmentToken(ctx, identity.EnrollmentTokenInput{
		NodeID:   *nodeID,
		Audience: *audience,
		TTL:      *ttl,
	})
	if err != nil {
		return fmt.Errorf("issue-enrollment-token: create token: %w", err)
	}
	if err := writeNewPrivateFile(*output, []byte(token.Value+"\n")); err != nil {
		return fmt.Errorf("issue-enrollment-token: persist one-time token: %w", err)
	}
	fmt.Fprintf(
		stdout,
		"enrollment token issued: id=%s node_id=%s audience=%s expires_at=%s output=%s\n",
		token.ID,
		token.NodeID,
		token.Audience,
		token.ExpiresAt.Format(time.RFC3339),
		*output,
	)
	return nil
}

func runCredentialStatus(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bonvoyage-control-plane credential-status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("credential-root", "", "absolute node credential directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*root) {
		return errors.New("credential-status: one absolute -credential-root is required")
	}
	status, err := nodecredentials.Status(*root, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("credential-status: %w", err)
	}
	fmt.Fprintf(
		stdout,
		"node credential: node_id=%s generation=%s spiffe_id=%s not_after=%s renew_after=%s renewal_due=%t expired=%t not_yet_valid=%t\n",
		status.NodeID,
		status.CredentialGeneration,
		status.SPIFFEID,
		status.NotAfter.Format(time.RFC3339),
		status.RenewAfter.Format(time.RFC3339),
		status.RenewalDue,
		status.Expired,
		status.NotYetValid,
	)
	return nil
}

func writeNewPrivateFile(path string, contents []byte) (returnErr error) {
	if len(contents) == 0 {
		return errors.New("output contents are empty")
	}
	if err := validateNewPrivateFileDestination(path); err != nil {
		return err
	}
	clean := filepath.Clean(path)
	file, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	removeIncomplete := true
	defer func() {
		if err := file.Close(); err != nil {
			returnErr = errors.Join(returnErr, err)
		}
		if removeIncomplete {
			_ = os.Remove(clean)
		}
	}()
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	removeIncomplete = false
	return nil
}

func validateNewPrivateFileDestination(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path {
		return errors.New("output path is invalid")
	}
	parent := filepath.Dir(clean)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output parent is not a real directory")
	}
	if _, err := os.Lstat(clean); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
