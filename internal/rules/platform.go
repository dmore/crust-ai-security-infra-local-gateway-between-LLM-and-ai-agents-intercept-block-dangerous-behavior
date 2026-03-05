package rules

import "github.com/BakeLens/crust/internal/platform"

// ShellEnv and its constants are re-exported from internal/platform for use
// within this package without a qualifier.
type ShellEnv = platform.ShellEnv

const (
	EnvUnix          = platform.Unix
	EnvWSL           = platform.WSL
	EnvWindowsNative = platform.WindowsNative
	EnvMSYS2         = platform.MSYS2
	EnvCygwin        = platform.Cygwin
)

// ShellEnvironment returns the detected shell/platform environment.
func ShellEnvironment() ShellEnv { return platform.Get() }
