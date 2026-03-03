package fileutil

import (
	"io"
	"os"
)

// ReadFileWithLock reads a file's contents while holding a shared (read) lock.
// On macOS/FreeBSD, the lock is acquired atomically with open via O_SHLOCK.
// On other platforms, the lock is acquired immediately after open.
func ReadFileWithLock(path string) ([]byte, error) {
	f, err := OpenReadLocked(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	defer Unlock(f)

	return io.ReadAll(f)
}

// WriteFileWithLock writes data to a file with 0600 permissions while holding
// an exclusive lock. The lock prevents concurrent reads from seeing partial data.
//
// SECURITY: The file is opened without O_TRUNC, and truncated only after
// acquiring the exclusive lock. This prevents a TOCTOU race where two
// concurrent writers both truncate before either locks.
func WriteFileWithLock(path string, data []byte) error {
	f, err := OpenExclusive(path, os.O_WRONLY|os.O_CREATE)
	if err != nil {
		return err
	}
	defer f.Close()
	defer Unlock(f)

	// Truncate and seek after lock — safe from concurrent writers.
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	_, err = f.Write(data)
	return err
}
