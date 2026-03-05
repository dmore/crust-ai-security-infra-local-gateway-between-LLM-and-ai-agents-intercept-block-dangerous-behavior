//go:build windows

package rules

import (
	"github.com/BakeLens/crust/internal/rules/pwsh"
)

// pwshTestResponse mirrors pwsh.Response but uses the rules-internal
// parsedCommand type so that extractor_windows_test.go can access
// resp.Commands[i] as *parsedCommand without an explicit conversion.
type pwshTestResponse struct {
	Commands    []parsedCommand
	ParseErrors []string
}

// pwshWorkerTestHelper wraps pwsh.Worker with lowercase method names so the
// Windows test file (extractor_windows_test.go) can call w.parse() and w.stop()
// without accessing the exported methods directly.
type pwshWorkerTestHelper struct {
	w *pwsh.Worker
}

// newPwshWorker creates a new pwshWorkerTestHelper backed by a real pwsh.Worker.
// Used by extractor_windows_test.go.
func newPwshWorker(pwshPath string) (*pwshWorkerTestHelper, error) {
	w, err := pwsh.NewWorker(pwshPath)
	if err != nil {
		return nil, err
	}
	return &pwshWorkerTestHelper{w: w}, nil
}

func (h *pwshWorkerTestHelper) parse(cmd string) (pwshTestResponse, error) {
	resp, err := h.w.Parse(cmd)
	if err != nil {
		return pwshTestResponse{}, err
	}
	out := pwshTestResponse{
		ParseErrors: resp.ParseErrors,
		Commands:    convertPSCommands(resp.Commands),
	}
	return out, nil
}

func (h *pwshWorkerTestHelper) stop() {
	h.w.Stop()
}
