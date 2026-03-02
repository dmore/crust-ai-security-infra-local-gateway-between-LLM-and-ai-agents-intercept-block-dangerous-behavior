package fileutil

import (
	"io"
	"os"
)

// ReadFileWithLock reads a file's contents while holding a shared (read) lock.
// This prevents reading a partially-written file when another process holds
// an exclusive lock for writing.
func ReadFileWithLock(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := LockShared(f); err != nil {
		return nil, err
	}
	defer Unlock(f)

	return io.ReadAll(f)
}

// WriteFileWithLock writes data to a file with 0600 permissions while holding
// an exclusive lock. The lock prevents concurrent reads from seeing partial data.
func WriteFileWithLock(path string, data []byte) error {
	f, err := SecureOpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := LockExclusive(f); err != nil {
		return err
	}
	defer Unlock(f)

	_, err = f.Write(data)
	return err
}
