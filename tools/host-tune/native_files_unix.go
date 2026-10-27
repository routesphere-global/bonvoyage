//go:build linux || darwin

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type nativeTuningFiles struct {
	root   *os.File
	uid    uint32
	locked bool
}

func openNativeTuningFiles(root string, uid uint32) (*nativeTuningFiles, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := &nativeTuningFiles{root: os.NewFile(uintptr(fd), root), uid: uid}
	if err = f.checkDirectory(fd); err != nil {
		f.root.Close()
		return nil, err
	}
	return f, nil
}
func (f *nativeTuningFiles) checkDirectory(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != f.uid || st.Mode&0o022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("native tuning requires owned, non-writable directory ancestry")
	}
	return nil
}
func (f *nativeTuningFiles) parent(name string) (*os.File, string, error) {
	if !strings.HasPrefix(name, "/") || path.Clean(name) != name || name == "/" {
		return nil, "", errors.New("invalid absolute contract path")
	}
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	fd, err := unix.Dup(int(f.root.Fd()))
	if err != nil {
		return nil, "", err
	}
	unix.CloseOnExec(fd)
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, "", e
		}
		fd = next
		if e = f.checkDirectory(fd); e != nil {
			unix.Close(fd)
			return nil, "", e
		}
	}
	return os.NewFile(uintptr(fd), "contract-parent"), parts[len(parts)-1], nil
}
func (f *nativeTuningFiles) readAt(parent *os.File, name string) (tuningValue, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return tuningValue{}, nil
	}
	if err != nil {
		return tuningValue{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return tuningValue{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != f.uid ||
		st.Mode&0o7022 != 0 || st.Size > 65536 {
		return tuningValue{}, errors.New("unsafe native tuning file type, owner, mode, link count or size")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return tuningValue{}, err
	}
	if len(data) > 65536 {
		return tuningValue{}, errors.New("native tuning file grew beyond limit")
	}
	return tuningValue{Exists: true, Data: data, Mode: uint32(st.Mode & 0o777), UID: int(st.Uid), GID: int(st.Gid)}, nil
}
func (f *nativeTuningFiles) readPath(name string) (tuningValue, error) {
	parent, base, err := f.parent(name)
	if err != nil {
		return tuningValue{}, err
	}
	defer parent.Close()
	return f.readAt(parent, base)
}

// Inspect on-disk overrides too: systemd's loaded DropInPaths can be stale.
func (f *nativeTuningFiles) validateManagedDirectories() error {
	for _, key := range []string{"service-resources", "irqbalance-exclusion"} {
		dir, _, err := f.parent(nativeControlPaths[key])
		if err != nil {
			return err
		}
		entries, err := dir.ReadDir(-1)
		dir.Close()
		if err != nil {
			return err
		}
		for _, entry := range entries {
			candidate := path.Dir(nativeControlPaths[key]) + "/" + entry.Name()
			allowed := false
			for _, owned := range nativeControlPaths {
				allowed = allowed || candidate == owned
			}
			if !allowed {
				return fmt.Errorf("unmanaged entry in service override directory: %s", candidate)
			}
		}
	}
	return nil
}

func (f *nativeTuningFiles) validateExecutable(name string) error {
	dir, base, err := f.parent(name)
	if err != nil {
		return err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != f.uid ||
		st.Mode&0o7022 != 0 || st.Mode&0o111 == 0 {
		return errors.New("unsafe native executable ownership, type or permissions")
	}
	return nil
}
func (f *nativeTuningFiles) Read(ctx context.Context, control string) (tuningValue, error) {
	if err := ctx.Err(); err != nil {
		return tuningValue{}, err
	}
	if !f.locked {
		return tuningValue{}, errors.New("native tuning lock required")
	}
	name, ok := nativeControlPaths[control]
	if !ok {
		return tuningValue{}, errors.New("unknown control")
	}
	value, err := f.readPath(name)
	if err != nil || !value.Exists {
		return value, err
	}
	value.Data, err = decodeNativeControl(control, value.Data)
	return value, err
}
func (f *nativeTuningFiles) Replace(ctx context.Context, control string, before, after tuningValue) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !f.locked {
		return errors.New("native tuning lock required")
	}
	name, ok := nativeControlPaths[control]
	if !ok {
		return errors.New("unknown control")
	}
	if !validTuningValue(after) || (after.Exists &&
		(after.UID != int(f.uid) || after.Mode&0o022 != 0)) {
		return errors.New("unsafe replacement metadata")
	}
	parent, base, err := f.parent(name)
	if err != nil {
		return err
	}
	defer parent.Close()
	current, err := f.readAt(parent, base)
	if err != nil {
		return err
	}
	if current.Exists {
		current.Data, err = decodeNativeControl(control, current.Data)
		if err != nil {
			return err
		}
	}
	if !equalTuningValue(current, before) {
		return errors.New("native control changed since capture")
	}
	if !after.Exists {
		if !before.Exists {
			return nil
		}
		if err = unix.Unlinkat(int(parent.Fd()), base, 0); err != nil {
			return err
		}
		return parent.Sync()
	}
	encoded, err := encodeNativeControl(control, after.Data)
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := ".bonvoyage-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(int(parent.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer func() { file.Close(); unix.Unlinkat(int(parent.Fd()), temporary, 0) }()
	if _, err = file.Write(encoded); err != nil {
		return err
	}
	if err = unix.Fchown(fd, after.UID, after.GID); err != nil {
		return err
	}
	if err = unix.Fchmod(fd, after.Mode); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// The advisory host lock serializes cooperating installers. Root administrators
	// must not edit concurrently; rename is atomic, but is not a filesystem CAS.
	again, err := f.readAt(parent, base)
	if err != nil {
		return err
	}
	if again.Exists {
		again.Data, err = decodeNativeControl(control, again.Data)
		if err != nil {
			return err
		}
	}
	if !equalTuningValue(again, before) {
		return errors.New("native control changed before replacement")
	}
	if err = unix.Renameat(int(parent.Fd()), temporary, int(parent.Fd()), base); err != nil {
		return err
	}
	return parent.Sync()
}
func (f *nativeTuningFiles) Lock(ctx context.Context) (func(), error) {
	if f.locked {
		return nil, errors.New("backend already owns a lock")
	}
	parent, base, err := f.parent("/run/bonvoyage-host-tune/host.lock")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), base, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "host-tuning-lock")
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		file.Close()
		return nil, err
	}
	if st.Uid != f.uid || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o7777 != 0o600 {
		file.Close()
		return nil, errors.New("unsafe host tuning lock")
	}
	for {
		if err = ctx.Err(); err != nil {
			file.Close()
			return nil, err
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			file.Close()
			return nil, fmt.Errorf("host lock: %w", err)
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	f.locked = true
	return func() { f.locked = false; unix.Flock(fd, unix.LOCK_UN); file.Close() }, nil
}
