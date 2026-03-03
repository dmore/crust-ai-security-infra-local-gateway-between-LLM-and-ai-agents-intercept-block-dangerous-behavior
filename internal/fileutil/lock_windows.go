//go:build windows

package fileutil

import (
	"os"

	"golang.org/x/sys/windows"
)

// LockShared acquires a shared (read) lock on f via LockFileEx.
// Blocks until the lock is available.
func LockShared(f *os.File) error {
	ol := &windows.Overlapped{}
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		0, // no flags = shared lock, blocking
		0, 1, 0,
		ol,
	)
}

// LockExclusive acquires an exclusive (write) lock on f via LockFileEx.
// Blocks until the lock is available.
func LockExclusive(f *os.File) error {
	ol := &windows.Overlapped{}
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0, 1, 0,
		ol,
	)
}

// TryLockExclusive attempts to acquire an exclusive lock on f without blocking.
// Returns an error immediately if the lock is held.
func TryLockExclusive(f *os.File) error {
	ol := &windows.Overlapped{}
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0,
		ol,
	)
}

// Unlock releases a lock on f via UnlockFileEx.
func Unlock(f *os.File) {
	ol := &windows.Overlapped{}
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol) //nolint:errcheck // best-effort unlock
}
