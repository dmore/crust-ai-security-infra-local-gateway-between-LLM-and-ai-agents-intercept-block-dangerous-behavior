//go:build !darwin && !freebsd

package fileutil

import "os"

// OpenReadLocked opens a file read-only with a shared advisory lock.
// On this platform (Linux, Windows), the lock is acquired as a separate
// flock()/LockFileEx call after open — a brief TOCTOU window exists.
func OpenReadLocked(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := LockShared(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// OpenExclusive opens a file with an exclusive advisory lock.
// On this platform, the lock is acquired after open. See OpenReadLocked.
// The file is created with 0600 permissions via SecureOpenFile.
func OpenExclusive(path string, flag int) (*os.File, error) {
	f, err := SecureOpenFile(path, flag)
	if err != nil {
		return nil, err
	}
	if err := LockExclusive(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
