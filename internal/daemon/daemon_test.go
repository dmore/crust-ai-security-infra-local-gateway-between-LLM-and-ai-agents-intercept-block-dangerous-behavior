//go:build unix

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BakeLens/crust/internal/fileutil"
)

func TestWritePID_ExclusiveLock(t *testing.T) {
	// Use a temp dir so we don't interfere with real PID files.
	tmpDir := t.TempDir()

	// Override pidFile() via a custom profile path isn't possible here since
	// pidFile() uses DataDir(). Instead, we test the flock logic directly.
	path := filepath.Join(tmpDir, "test.pid")

	// Acquire lock manually
	f1, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f1.Close()

	if err := fileutil.TryLockExclusive(f1); err != nil {
		t.Fatalf("first lock: %v", err)
	}

	// Second attempt should fail (EWOULDBLOCK)
	f2, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	defer f2.Close()

	err = fileutil.TryLockExclusive(f2)
	if err == nil {
		t.Fatal("second lock should fail when first holds lock")
	}

	// Release first lock
	fileutil.Unlock(f1)

	// Now second should succeed
	if err := fileutil.TryLockExclusive(f2); err != nil {
		t.Fatalf("lock after release should succeed: %v", err)
	}
}
