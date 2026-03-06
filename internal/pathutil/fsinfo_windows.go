//go:build windows

package pathutil

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// DetectFS queries filesystem properties for the volume containing path.
//
// Strategy (two-phase):
//  1. GetVolumeInformation — fast, zero I/O. If the volume flag is NOT set
//     (FILE_CASE_SENSITIVE_SEARCH == 0), we are definitely case-insensitive.
//  2. If the volume flag IS set, it only means NTFS *supports* case-sensitive
//     names — it doesn't mean the directory is actually case-sensitive. Windows 10+
//     allows per-directory case sensitivity (opt-in via fsutil or WSL2), so the
//     volume flag can be set while most user directories remain case-insensitive.
//     In that case we do a runtime probe at the target path to confirm.
func DetectFS(path string) FSInfo {
	// Phase 1: volume-level flag via GetVolumeInformation.
	vol := filepath.VolumeName(path)
	if vol == "" {
		return FSInfo{CaseSensitive: false}
	}
	root := vol + `\`

	var flags uint32
	rootPtr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return FSInfo{CaseSensitive: false}
	}

	err = windows.GetVolumeInformation(
		rootPtr,
		nil, 0,
		nil,
		nil,
		&flags,
		nil, 0,
	)
	if err != nil {
		return FSInfo{CaseSensitive: false}
	}

	if flags&windows.FILE_CASE_SENSITIVE_SEARCH == 0 {
		// Volume is case-insensitive — no probe needed.
		return FSInfo{CaseSensitive: false}
	}

	// Phase 2: volume flag says case-sensitive, but per-directory settings
	// may override (common on MSYS2/WSL2 developer machines). Probe the
	// actual directory to get the real behavior.
	return FSInfo{CaseSensitive: probeCS(path)}
}

// probeCS creates a temp file in dir and tries to open it with different case.
// Returns true (case-sensitive) if the OS cannot find the file under alternate case.
// Falls back to true (safe/conservative) on any I/O error.
func probeCS(dir string) bool {
	// Ensure dir exists and is a directory.
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		dir = filepath.Dir(dir)
	}

	// Create a file with a mixed-case prefix so we can probe with lower/upper.
	f, err := os.CreateTemp(dir, "CrustCSProbe")
	if err != nil {
		return true // can't probe — stay conservative
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)

	base := filepath.Base(name)
	altBase := strings.ToLower(base)
	if altBase == base {
		altBase = strings.ToUpper(base)
		if altBase == base {
			return true // all digits/symbols — can't distinguish
		}
	}
	altPath := filepath.Join(filepath.Dir(name), altBase)

	_, err = os.Stat(altPath) //nolint:gosec // altPath is filepath.Join(os.TempDir(), caseVariantOfOSGeneratedName) — no traversal possible
	// If err is nil → OS found the file under different case → case-insensitive.
	// Any error (IsNotExist OR access-denied/I/O error) → conservative: case-sensitive.
	// Returning true on non-IsNotExist errors matches the "Falls back to true" contract
	// in the function comment. Returning false (case-insensitive) on arbitrary I/O
	// errors would be the wrong safe default.
	return err != nil
}
