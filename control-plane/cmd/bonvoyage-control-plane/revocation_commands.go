package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/routesphere-global/bonvoyage/control-plane/internal/discovery"
)

const defaultRevocationValidity = 7 * 24 * time.Hour

func runInitializeRevocations(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bonvoyage-control-plane initialize-revocations", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("revocation-file", "", "new absolute revocation snapshot path")
	validFor := flags.Duration("valid-for", defaultRevocationValidity, "freshness window before authentication fails closed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*path) {
		return errors.New("initialize-revocations: one absolute -revocation-file is required")
	}
	document, err := discovery.InitializeRevocationDocument(*path, time.Now().UTC(), *validFor)
	if err != nil {
		return fmt.Errorf("initialize-revocations: %w", err)
	}
	printRevocationStatus("revocation snapshot initialized", *path, document, stdout)
	return nil
}

func runRefreshRevocations(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bonvoyage-control-plane refresh-revocations", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("revocation-file", "", "absolute revocation snapshot path")
	validFor := flags.Duration("valid-for", defaultRevocationValidity, "new freshness window before authentication fails closed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*path) {
		return errors.New("refresh-revocations: one absolute -revocation-file is required")
	}
	document, err := discovery.RefreshRevocationDocument(*path, time.Now().UTC(), *validFor)
	if err != nil {
		return fmt.Errorf("refresh-revocations: %w", err)
	}
	printRevocationStatus("revocation snapshot refreshed", *path, document, stdout)
	return nil
}

func runRevokeNode(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bonvoyage-control-plane revoke-node", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("revocation-file", "", "absolute revocation snapshot path")
	nodeID := flags.String("node-id", "", "exact node ID to revoke")
	reason := flags.String("reason", "", "bounded operator reason")
	validFor := flags.Duration("valid-for", defaultRevocationValidity, "new freshness window before authentication fails closed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*path) || strings.TrimSpace(*nodeID) == "" ||
		strings.TrimSpace(*reason) == "" {
		return errors.New("revoke-node: revocation file, node ID, and reason are required")
	}
	document, err := discovery.AddNodeRevocation(
		*path,
		*nodeID,
		*reason,
		time.Now().UTC(),
		*validFor,
	)
	if err != nil {
		return fmt.Errorf("revoke-node: %w", err)
	}
	printRevocationStatus("node revoked", *path, document, stdout)
	return nil
}

func printRevocationStatus(
	prefix string,
	path string,
	document discovery.RevocationDocument,
	stdout io.Writer,
) {
	fmt.Fprintf(
		stdout,
		"%s: generation=%d entries=%d valid_until=%s path=%s\n",
		prefix,
		document.Generation,
		len(document.Revoked),
		document.ValidUntil.Format(time.RFC3339),
		path,
	)
}
