package rules

import (
	"fmt"
	"sync"

	"github.com/zricethezav/gitleaks/v8/detect"
)

// DLPScanner provides secret detection via the gitleaks library (in-process).
// The detector is created once at init and reused for all scans.
type DLPScanner struct {
	detector   *detect.Detector // created once, reused
	available  bool
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
func newDLPScanner(disabled bool) (*DLPScanner, error) {
	if disabled {
		return &DLPScanner{}, nil
	}
	return NewDLPScanner()
}

// NewDLPScanner creates a scanner with the default gitleaks config.
func NewDLPScanner() (*DLPScanner, error) {
	det, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("gitleaks detector init: %w", err)
	}

	log.Info("DLP enabled: gitleaks library loaded (in-process)")
	return &DLPScanner{detector: det, available: true}, nil
}

// Available reports whether gitleaks is loaded.
func (s *DLPScanner) Available() bool {
	return s != nil && s.available
}

// Scan checks content for secrets using gitleaks. Returns nil if unavailable.
func (s *DLPScanner) Scan(content string) (findings []DLPFinding) {
	if !s.Available() || content == "" {
		return nil
	}

	s.mu.Lock()
	s.scanCount++
	s.mu.Unlock()

	// recover() catches any panic in gitleaks (pure Go, no segfaults).
	defer func() {
		if r := recover(); r != nil {
			log.Warn("DLP gitleaks panic (recovered): %v", r)
			findings = nil
		}
	}()

	results := s.detector.DetectString(content)
	if len(results) == 0 {
		return nil
	}

	s.mu.Lock()
	s.blockCount += int64(len(results))
	s.mu.Unlock()

	findings = make([]DLPFinding, len(results))
	for i, f := range results {
		findings[i] = DLPFinding{
			RuleID:      f.RuleID,
			Description: f.Description,
			Match:       f.Match,
			StartLine:   f.StartLine,
		}
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
