//go:build windows

package config

import (
	"os"

	"github.com/BakeLens/crust/internal/fileutil"
)

func lockShared(f *os.File) error    { return fileutil.LockShared(f) }
func lockExclusive(f *os.File) error { return fileutil.LockExclusive(f) }
func unlock(f *os.File)              { fileutil.Unlock(f) }
