//go:build !windows

package fileutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// LockShared acquires a shared (read) advisory lock on f.
// Blocks until the lock is available.
func LockShared(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_SH) //nolint:gosec // Fd() fits int on all supported platforms
}

// LockExclusive acquires an exclusive (write) advisory lock on f.
// Blocks until the lock is available.
func LockExclusive(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX) //nolint:gosec // Fd() fits int on all supported platforms
}

// Unlock releases an advisory lock on f.
func Unlock(f *os.File) {
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN) //nolint:gosec,errcheck // best-effort unlock
}
