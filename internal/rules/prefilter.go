package rules

import (
	"regexp"
)

// PreFilter detects encoding-based obfuscation (base64, hex) that hides
// the actual command from the shell parser. Other detections (eval, fork bombs,
// network exfiltration, IFS) are handled by the shell parser + command DB.
type PreFilter struct {
	patterns []*CompiledPreFilterPattern
}

// CompiledPreFilterPattern is a pre-compiled obfuscation pattern
type CompiledPreFilterPattern struct {
	Name    string
	Pattern *regexp.Regexp
	Reason  string
}

// PreFilterMatch represents a match from the pre-filter
type PreFilterMatch struct {
	PatternName string
	Reason      string
	Matched     string // The matched substring
}

// NewPreFilter creates a new PreFilter with default obfuscation patterns
func NewPreFilter() *PreFilter {
	pf := &PreFilter{}
	pf.compilePatterns(defaultPreFilterPatterns)
	return pf
}

// NewPreFilterWithPatterns creates a PreFilter with custom patterns
func NewPreFilterWithPatterns(patterns []PreFilterPatternDef) *PreFilter {
	pf := &PreFilter{}
	pf.compilePatterns(patterns)
	return pf
}

// PreFilterPatternDef defines an obfuscation pattern
type PreFilterPatternDef struct {
	Name    string
	Pattern string
	Reason  string
}

// compilePatterns compiles the pattern definitions
func (pf *PreFilter) compilePatterns(defs []PreFilterPatternDef) {
	pf.patterns = make([]*CompiledPreFilterPattern, 0, len(defs))
	for _, def := range defs {
		re, err := regexp.Compile(def.Pattern)
		if err != nil {
			// Skip invalid patterns but log them
			log.Warn("Invalid pre-filter pattern %s: %v", def.Name, err)
			continue
		}
		pf.patterns = append(pf.patterns, &CompiledPreFilterPattern{
			Name:    def.Name,
			Pattern: re,
			Reason:  def.Reason,
		})
	}
}

// Check checks a command for obfuscation patterns.
// Returns the first match found, or nil if no patterns match.
func (pf *PreFilter) Check(cmd string) *PreFilterMatch {
	for _, p := range pf.patterns {
		if match := p.Pattern.FindString(cmd); match != "" {
			return &PreFilterMatch{
				PatternName: p.Name,
				Reason:      p.Reason,
				Matched:     match,
			}
		}
	}
	return nil
}

// CheckAll checks a command and returns ALL matches (for comprehensive logging)
func (pf *PreFilter) CheckAll(cmd string) []*PreFilterMatch {
	var matches []*PreFilterMatch
	for _, p := range pf.patterns {
		if match := p.Pattern.FindString(cmd); match != "" {
			matches = append(matches, &PreFilterMatch{
				PatternName: p.Name,
				Reason:      p.Reason,
				Matched:     match,
			})
		}
	}
	return matches
}

// ContainsObfuscation is a quick check that returns true if any obfuscation is detected
func (pf *PreFilter) ContainsObfuscation(cmd string) bool {
	return pf.Check(cmd) != nil
}

// defaultPreFilterPatterns contains patterns for common obfuscation techniques.
//
// NOTE: command-substitution ($(), backticks) and process-substitution (<(), >())
// are intentionally NOT included. The shell interpreter expands $() in dry-run
// mode, so paths inside substitutions are correctly extracted and matched against
// rules. Process substitution is handled by nodeHasUnsafe (ProcSubst case).
// Blocking these at the PreFilter level caused false positives on normal agent
// commands like "cd $(git rev-parse --show-toplevel)" and "diff <(sort a) <(sort b)".
var defaultPreFilterPatterns = []PreFilterPatternDef{
	// Base64 decoding - commonly used to hide payloads
	{
		Name:    "base64-decode",
		Pattern: `base64\s+(-d|--decode)`,
		Reason:  "base64 decode (hiding payload)",
	},
	{
		Name:    "base64-pipe-decode",
		Pattern: `\|\s*base64\s+(-d|--decode)`,
		Reason:  "piped base64 decode",
	},

	// Hex encoding — require 3+ consecutive hex escapes.
	// Single \x00 (grep for nulls) and \x1b (ANSI colors) are normal.
	// 3+ consecutive hex escapes indicate encoded command/path hiding
	// (e.g., \x63\x61\x74 = "cat").
	{
		Name:    "hex-escape",
		Pattern: `(\\x[0-9a-fA-F]{2}){3,}`,
		Reason:  "multiple hex escape sequences (possible encoded command)",
	},

	// Fork bombs are detected at the AST level (astForkBomb in extractor.go)
	// which catches all variants, not just regex-matchable patterns.
}
