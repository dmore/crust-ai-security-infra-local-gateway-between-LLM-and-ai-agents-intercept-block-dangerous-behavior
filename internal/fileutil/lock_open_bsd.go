//go:build darwin || freebsd

package fileutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// OpenReadLocked opens a file read-only with a shared advisory lock.
// On BSD (macOS, FreeBSD), the lock is acquired atomically via O_SHLOCK —
// no TOCTOU gap between open and lock.
func OpenReadLocked(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_SHLOCK, 0)
}

// OpenExclusive opens a file with an exclusive advisory lock.
// On BSD (macOS, FreeBSD), the lock is acquired atomically via O_EXLOCK.
// The file is created with 0600 permissions via SecureOpenFile.
func OpenExclusive(path string, flag int) (*os.File, error) {
	return SecureOpenFile(path, flag|unix.O_EXLOCK)
}
