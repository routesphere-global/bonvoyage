//go:build darwin || linux

package identity

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

type repositoryLock struct {
	file *os.File
}

func acquireRepositoryLock(path string) (*repositoryLock, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
			hasUnsafePermissionBits(info.Mode()) {
			return nil, fmt.Errorf("identity repository lock has unsafe type or permissions: %w", ErrInvalid)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect identity repository lock: %w", err)
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open identity repository lock without following links: %w: %w", ErrInvalid, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("construct identity repository lock file: %w", ErrInvalid)
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || hasUnsafePermissionBits(opened.Mode()) {
		_ = file.Close()
		return nil, fmt.Errorf("identity repository lock is not a regular file: %w", ErrInvalid)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("set identity repository lock permissions: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("acquire identity repository lock: %w", err)
	}
	return &repositoryLock{file: file}, nil
}

func (lock *repositoryLock) release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return fmt.Errorf("release identity repository lock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close identity repository lock: %w", closeErr)
	}
	return nil
}
