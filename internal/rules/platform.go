package rules

import (
	"os"
	"runtime"
)

// isNativeWindowsEnv returns true when the process is running in a native
// Windows shell environment (cmd.exe or PowerShell) where .NET APIs and
// PowerShell syntax work as expected.
//
// It returns false on Unix-like emulation layers that report GOOS=windows
// but use a bash-compatible shell (MSYS2, Cygwin, Git Bash). These
// environments set the MSYSTEM or CYGWIN environment variables.
func isNativeWindowsEnv() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	return os.Getenv("MSYSTEM") == "" && os.Getenv("CYGWIN") == ""
}
