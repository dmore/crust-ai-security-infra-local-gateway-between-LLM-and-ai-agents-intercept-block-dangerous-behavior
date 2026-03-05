package platform_test

import (
	"runtime"
	"testing"

	"github.com/BakeLens/crust/internal/platform"
)

func TestShellEnv_Values(t *testing.T) {
	// Each constant must have a distinct, non-empty string value.
	envs := []platform.ShellEnv{platform.Unix, platform.WSL, platform.WindowsNative, platform.MSYS2, platform.Cygwin}
	seen := make(map[platform.ShellEnv]bool)
	for _, e := range envs {
		if string(e) == "" {
			t.Errorf("ShellEnv %q has empty string value", e)
		}
		if seen[e] {
			t.Errorf("duplicate ShellEnv value %q", e)
		}
		seen[e] = true
	}
}

func TestShellEnv_IsWindows(t *testing.T) {
	cases := []struct {
		env  platform.ShellEnv
		want bool
	}{
		{platform.Unix, false},
		{platform.WSL, false},
		{platform.WindowsNative, true},
		{platform.MSYS2, true},
		{platform.Cygwin, true},
	}
	for _, tc := range cases {
		if got := tc.env.IsWindows(); got != tc.want {
			t.Errorf("%v.IsWindows() = %v, want %v", tc.env, got, tc.want)
		}
	}
}

func TestShellEnv_HasBash(t *testing.T) {
	cases := []struct {
		env  platform.ShellEnv
		want bool
	}{
		{platform.Unix, true},
		{platform.WSL, true},
		{platform.WindowsNative, false},
		{platform.MSYS2, true},
		{platform.Cygwin, true},
	}
	for _, tc := range cases {
		if got := tc.env.HasBash(); got != tc.want {
			t.Errorf("%v.HasBash() = %v, want %v", tc.env, got, tc.want)
		}
	}
}

func TestShellEnv_HasPwsh(t *testing.T) {
	cases := []struct {
		env  platform.ShellEnv
		want bool
	}{
		{platform.Unix, false},
		{platform.WSL, false},
		{platform.WindowsNative, true},
		{platform.MSYS2, true},
		{platform.Cygwin, false},
	}
	for _, tc := range cases {
		if got := tc.env.HasPwsh(); got != tc.want {
			t.Errorf("%v.HasPwsh() = %v, want %v", tc.env, got, tc.want)
		}
	}
}

func TestShellEnv_Exclusive(t *testing.T) {
	// Environments are mutually exclusive: flag combinations are well-defined.
	type flags struct{ isWin, hasBash, hasPwsh bool }
	cases := map[platform.ShellEnv]flags{
		platform.Unix:          {false, true, false},
		platform.WSL:           {false, true, false},
		platform.WindowsNative: {true, false, true},
		platform.MSYS2:         {true, true, true},
		platform.Cygwin:        {true, true, false},
	}
	for env, want := range cases {
		got := flags{env.IsWindows(), env.HasBash(), env.HasPwsh()}
		if got != want {
			t.Errorf("%v: got {isWin:%v hasBash:%v hasPwsh:%v}, want {isWin:%v hasBash:%v hasPwsh:%v}",
				env, got.isWin, got.hasBash, got.hasPwsh,
				want.isWin, want.hasBash, want.hasPwsh)
		}
	}
}

func TestGet_CurrentProcess(t *testing.T) {
	got := platform.Get()
	switch runtime.GOOS {
	case "windows":
		if !got.IsWindows() {
			t.Errorf("GOOS=windows but platform.Get()=%v is not Windows", got)
		}
	case "linux", "darwin":
		if got.IsWindows() {
			t.Errorf("GOOS=%s but platform.Get()=%v reports Windows", runtime.GOOS, got)
		}
	}
}
