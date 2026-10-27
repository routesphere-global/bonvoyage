package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create private identity directory %q: %w", path, err)
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect identity directory %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("identity path %q is not a real directory: %w", path, ErrInvalid)
	}
	if info.Mode().Perm()&0o077 != 0 || hasUnsafePermissionBits(info.Mode()) {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("restrict identity directory %q permissions: %w", path, err)
		}
	}
	return nil
}

func ensurePrivateDirectoryTree(path string) error {
	var missing []string
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("identity path %q is not a real directory: %w", current, ErrInvalid)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect identity directory %q: %w", current, err)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("identity path has no existing ancestor: %w", ErrInvalid)
		}
		current = parent
	}
	for index := len(missing) - 1; index >= 0; index-- {
		if err := ensurePrivateDirectory(missing[index]); err != nil {
			return err
		}
	}
	return ensurePrivateDirectory(path)
}

func readPrivateFile(path string, maxBytes int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		hasUnsafePermissionBits(info.Mode()) {
		return nil, fmt.Errorf("file %q has unsafe type or permissions: %w", path, ErrCorrupt)
	}
	return readBoundedFile(path, maxBytes, info)
}

func readOperatorFile(path string, maxBytes int, private bool) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("operator file path is empty: %w", ErrInvalid)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 || !mode.IsRegular() || hasUnsafePermissionBits(mode) {
		return nil, fmt.Errorf("operator file %q has an unsafe type: %w", path, ErrInvalid)
	}
	permissions := mode.Perm()
	if permissions&0o400 == 0 || private && permissions&0o177 != 0 ||
		!private && permissions&0o133 != 0 {
		return nil, fmt.Errorf("operator file %q has unsafe permissions %o: %w", path, permissions, ErrInvalid)
	}
	return readBoundedFile(path, maxBytes, info)
}

func readBoundedFile(path string, maxBytes int, expected os.FileInfo) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file %q: %w", path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened file %q: %w", path, err)
	}
	if !opened.Mode().IsRegular() || opened.Mode().Perm() != expected.Mode().Perm() ||
		hasUnsafePermissionBits(opened.Mode()) != hasUnsafePermissionBits(expected.Mode()) || !os.SameFile(expected, opened) {
		return nil, fmt.Errorf("file %q changed during secure open: %w", path, ErrInvalid)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", path, err)
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("file %q exceeds %d bytes: %w", path, maxBytes, ErrInvalid)
	}
	return data, nil
}

func hasUnsafePermissionBits(mode os.FileMode) bool {
	return mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0
}

func writeFileAtomicPrivate(path string, data []byte) (returnErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".bonvoyage-identity-*")
	if err != nil {
		return fmt.Errorf("create temporary identity file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if returnErr != nil {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary identity file permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write temporary identity file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary identity file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary identity file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("atomically replace identity file: %w", err)
	}
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open identity directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync identity directory: %w", err)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing identity state: %w: %w", ErrCorrupt, err)
	}
	return fmt.Errorf("identity state contains multiple JSON values: %w", ErrCorrupt)
}

func strictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode identity state: %w: %w", ErrCorrupt, err)
	}
	return requireJSONEOF(decoder)
}
