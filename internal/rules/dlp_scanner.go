package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// DLPScanner provides Tier 2 secret detection via an external gitleaks binary.
// Recommended dependency — logs a warning with install instructions if missing.
type DLPScanner struct {
	binaryPath string
	available  bool
	timeout    time.Duration
	mu         sync.RWMutex
	scanCount  int64
	blockCount int64
}

// DLPFinding represents a single secret detected by gitleaks.
type DLPFinding struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	Match       string `json:"Match"`
	StartLine   int    `json:"StartLine"`
}

// newDLPScanner creates a scanner, optionally disabled (e.g., for fuzz/unit tests).
func newDLPScanner(disabled bool) *DLPScanner {
	if disabled {
		return &DLPScanner{timeout: 5 * time.Second}
	}
	return NewDLPScanner()
}

// NewDLPScanner creates a scanner. Returns a disabled scanner if gitleaks is not in PATH.
func NewDLPScanner() *DLPScanner {
	s := &DLPScanner{
		timeout: 5 * time.Second,
	}

	path, err := exec.LookPath("gitleaks")
	if err != nil {
		log.Warn("DLP Tier 2 disabled: gitleaks not found — install for full secret detection (200+ patterns)")
		log.Warn("  brew install gitleaks  OR  go install github.com/zricethezav/gitleaks/v8@latest")
		return s
	}

	s.binaryPath = path
	s.available = true
	log.Info("DLP Tier 2 enabled: gitleaks found at %s", path)
	return s
}

// Available reports whether gitleaks is installed.
func (s *DLPScanner) Available() bool {
	return s != nil && s.available
}

// Scan checks content for secrets using gitleaks. Returns nil if unavailable.
func (s *DLPScanner) Scan(content string) []DLPFinding {
	if !s.Available() || content == "" {
		return nil
	}

	s.mu.Lock()
	s.scanCount++
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	findings := s.runGitleaks(ctx, content, "stdin")
	if findings == nil {
		findings = s.runGitleaks(ctx, content, "detect", "--pipe") // older gitleaks
	}

	if len(findings) > 0 {
		s.mu.Lock()
		s.blockCount += int64(len(findings))
		s.mu.Unlock()
	}

	return findings
}

// runGitleaks executes gitleaks and returns parsed findings.
func (s *DLPScanner) runGitleaks(ctx context.Context, content string, args ...string) []DLPFinding {
	cmdArgs := make([]string, 0, len(args)+5)
	cmdArgs = append(cmdArgs, args...)
	cmdArgs = append(cmdArgs, "--report-format", "json", "--no-banner", "--exit-code", "0")
	cmd := exec.CommandContext(ctx, s.binaryPath, cmdArgs...) //nolint:gosec // binaryPath is resolved via exec.LookPath at init
	// WaitDelay forces stdin/stdout goroutines to stop 1s after context cancels.
	// Without this, a timed-out or killed gitleaks process leaves pipe goroutines
	// blocked indefinitely — particularly on Windows where killing a process does
	// not automatically close its pipe handles.
	cmd.WaitDelay = 1 * time.Second
	cmd.Stdin = strings.NewReader(content)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			log.Warn("DLP Tier 2 scan timed out after %s", s.timeout)
		}
		return nil
	}

	output := stdout.Bytes()
	if len(output) == 0 {
		return nil
	}

	var findings []DLPFinding
	if err := json.Unmarshal(output, &findings); err != nil {
		return nil
	}

	return findings
}

// Stats returns scan statistics.
func (s *DLPScanner) Stats() (scans, blocks int64) {
	if s == nil {
		return 0, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scanCount, s.blockCount
}
