package rules

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/pathutil"
	"github.com/gobwas/glob"
)

// expandRuleHomes replaces $HOME in rule path patterns with the actual home
// directory. This allows YAML rules to use "$HOME/.ssh/id_*" instead of
// enumerating OS-specific paths. Called before compileRules() so glob patterns
// contain real paths.
func expandRuleHomes(rules []Rule, homeDir string) []Rule {
	if homeDir == "" {
		return rules
	}
	home := pathutil.ToSlash(homeDir)
	for i := range rules {
		for j, p := range rules[i].Block.Paths {
			rules[i].Block.Paths[j] = strings.ReplaceAll(p, "$HOME", home)
		}
		for j, p := range rules[i].Block.Except {
			rules[i].Block.Except[j] = strings.ReplaceAll(p, "$HOME", home)
		}
		// Expand in Match.Path (Level 4+ rules)
		if rules[i].Match != nil && strings.Contains(rules[i].Match.Path, "$HOME") {
			rules[i].Match.Path = strings.ReplaceAll(rules[i].Match.Path, "$HOME", home)
		}
		// Expand in AllConditions and AnyConditions
		for j := range rules[i].AllConditions {
			if strings.Contains(rules[i].AllConditions[j].Path, "$HOME") {
				rules[i].AllConditions[j].Path = strings.ReplaceAll(rules[i].AllConditions[j].Path, "$HOME", home)
			}
		}
		for j := range rules[i].AnyConditions {
			if strings.Contains(rules[i].AnyConditions[j].Path, "$HOME") {
				rules[i].AnyConditions[j].Path = strings.ReplaceAll(rules[i].AnyConditions[j].Path, "$HOME", home)
			}
		}
	}
	return rules
}

var log = logger.New("rules")

// Engine is the path-based rule engine
type Engine struct {
	mu sync.RWMutex

	// Immutable after init; --disable-builtin filters to locked-only
	builtin []CompiledRule

	// Can be hot-reloaded
	user []CompiledRule

	// Merged and sorted by priority (rebuilt on reload)
	merged []CompiledRule

	// Core components
	extractor  *Extractor
	normalizer *Normalizer
	loader     *Loader
	preFilter  *PreFilter
	dlpScanner *DLPScanner

	// Configuration
	config EngineConfig

	// Stats
	hitCounts map[string]*int64

	// Pre-checker runs before the evaluation pipeline (e.g., self-protection).
	preChecker func(rawJSON string) *MatchResult

	// Close guard
	closeOnce sync.Once

	// Callbacks for reload notifications
	onReloadCallbacks []ReloadCallback
}

// CompiledMatch holds pre-compiled patterns from a Match condition.
// All regex/glob patterns are validated and compiled at rule insert time,
// so evaluation never needs to re-compile or handle invalid patterns.
type CompiledMatch struct {
	Match        Match          // original for error messages/display
	PathRegex    *regexp.Regexp // non-nil if Match.Path starts with "re:"
	PathGlob     glob.Glob      // non-nil if Match.Path is a glob pattern
	CommandRegex *regexp.Regexp // non-nil if Match.Command starts with "re:"
	HostRegex    *regexp.Regexp // non-nil if Match.Host starts with "re:"
	HostGlob     glob.Glob      // non-nil if Match.Host is a glob pattern
	ContentRegex *regexp.Regexp // non-nil if Match.Content starts with "re:"
}

// CompiledRule is a rule with pre-compiled matchers
type CompiledRule struct {
	Rule        Rule
	PathMatcher *Matcher // pre-compiled Block.Paths/Except
	HostMatcher *Matcher // pre-compiled Block.Hosts

	// Pre-compiled Match patterns (Level 4+ rules)
	MatchCompiled      *CompiledMatch
	AllCompiledMatches []CompiledMatch
	AnyCompiledMatches []CompiledMatch
}

// EngineConfig holds engine configuration
type EngineConfig struct {
	UserRulesDir        string
	DisableBuiltin      bool
	DisableDLP          bool // Skip gitleaks-based DLP scanning (useful in fuzz/unit tests)
	SubprocessIsolation bool // Isolate shell interpreter in a subprocess for crash safety

	// PreChecker is called before the evaluation pipeline (e.g., self-protection).
	// Injected at construction time to avoid circular imports with selfprotect.
	PreChecker func(rawJSON string) *MatchResult
}

// ReloadCallback is called after rules are reloaded
type ReloadCallback func(rules []Rule)

// SECURITY FIX: Use mutex to prevent race conditions on global engine access
var (
	globalEngine   *Engine
	globalEngineMu sync.RWMutex
)

// SetGlobalEngine sets the global rule engine instance
func SetGlobalEngine(e *Engine) {
	globalEngineMu.Lock()
	defer globalEngineMu.Unlock()
	globalEngine = e
}

// GetGlobalEngine returns the global rule engine instance
func GetGlobalEngine() *Engine {
	globalEngineMu.RLock()
	defer globalEngineMu.RUnlock()
	return globalEngine
}

// NewEngine creates a new path-based rule engine
func NewEngine(cfg EngineConfig) (*Engine, error) {
	return NewEngineWithNormalizer(cfg, NewNormalizer())
}

// NewEngineWithNormalizer creates a new engine with a custom normalizer.
// The normalizer is used from the start so $HOME in YAML rules expands
// to the normalizer's home directory before pattern compilation.
func NewEngineWithNormalizer(cfg EngineConfig, normalizer *Normalizer) (*Engine, error) {
	loader := NewLoader(cfg.UserRulesDir)

	// Build extractor env that matches normalizer so shell interpreter
	// and path normalization agree on HOME, etc.
	extEnv := make(map[string]string, len(normalizer.env)+1)
	maps.Copy(extEnv, normalizer.env)
	if h := normalizer.GetHomeDir(); h != "" {
		extEnv["HOME"] = h
	}

	dlp, err := newDLPScanner(cfg.DisableDLP)
	if err != nil {
		return nil, fmt.Errorf("DLP init: %w", err)
	}

	e := &Engine{
		extractor:  NewExtractorWithEnv(extEnv),
		normalizer: normalizer,
		loader:     loader,
		preFilter:  NewPreFilter(),
		dlpScanner: dlp,
		config:     cfg,
		preChecker: cfg.PreChecker,
		hitCounts:  make(map[string]*int64),
	}

	if cfg.SubprocessIsolation {
		if exe, err := os.Executable(); err == nil {
			if err := e.extractor.EnableSubprocessIsolation(exe); err != nil {
				log.Warn("Shell worker failed to start (falling back to in-process): %v", err)
			}
		}
	}

	if runtime.GOOS == goosWindows {
		// Windows 10/11 always ships powershell.exe (5.1); pwsh.exe (7+) is
		// optional. FindPwsh() should always succeed on supported platforms.
		if pwshPath, ok := FindPwsh(); ok {
			if err := e.extractor.EnablePSWorker(pwshPath); err != nil {
				log.Warn("PS worker failed to start (falling back to heuristic PS transform): %v", err)
			}
		} else {
			log.Warn("powershell.exe not found — PS analysis degraded (unsupported Windows configuration)")
		}
	}

	// Load builtin rules
	builtinRules, err := loader.LoadBuiltin()
	if err != nil {
		return nil, err
	}

	// Add dynamic protection rules based on config (always locked)
	dynamicRules := generateProtectionRules(cfg)
	builtinRules = append(dynamicRules, builtinRules...)

	if cfg.DisableBuiltin {
		// Keep only locked rules — they cannot be disabled
		var locked []Rule
		for _, r := range builtinRules {
			if r.IsLocked() {
				locked = append(locked, r)
			}
		}
		log.Warn("Builtin rules disabled (%d locked rules remain active)", len(locked))
		builtinRules = locked
	}

	// Expand $HOME in YAML rule paths to actual home directory
	builtinRules = expandRuleHomes(builtinRules, normalizer.GetHomeDir())

	compiled, err := e.compileRules(builtinRules, true)
	if err != nil {
		return nil, err
	}
	e.builtin = compiled
	if !cfg.DisableBuiltin {
		log.Info("Loaded %d builtin rules (%d dynamic)", len(compiled), len(dynamicRules))
	}

	// Load user rules
	if err := e.ReloadUserRules(); err != nil {
		log.Warn("Failed to load user rules: %v", err)
		// Ensure builtin rules are merged even if user rules fail to load
		e.mu.Lock()
		e.rebuildMergedLocked()
		e.mu.Unlock()
	}

	return e, nil
}

// NewTestEngine creates a new engine from a list of rules.
// This is a convenience function for testing that bypasses loading from files.
func NewTestEngine(rules []Rule) (*Engine, error) {
	e := &Engine{
		extractor:  NewExtractor(),
		normalizer: NewNormalizer(),
		loader:     NewLoader(""),
		preFilter:  NewPreFilter(),
		dlpScanner: &DLPScanner{},
		config:     EngineConfig{DisableBuiltin: true},
		hitCounts:  make(map[string]*int64),
	}

	compiled, err := e.compileRules(rules, true)
	if err != nil {
		return nil, err
	}
	e.builtin = compiled
	e.rebuildMergedLocked()

	return e, nil
}

// NewTestEngineWithNormalizer creates a new engine with a custom normalizer.
// This is useful for testing with controlled environment variables.
func NewTestEngineWithNormalizer(rules []Rule, normalizer *Normalizer) (*Engine, error) {
	engine, err := NewTestEngine(rules)
	if err != nil {
		return nil, err
	}
	engine.normalizer = normalizer
	// Match the extractor's env to the normalizer's env so variable
	// expansion ($HOME, etc.) resolves consistently in tests.
	engine.extractor = NewExtractorWithEnv(normalizer.env)
	return engine, nil
}

// generateProtectionRules creates dynamic rules to protect Crust itself
func generateProtectionRules(cfg EngineConfig) []Rule {
	rules := []Rule{}

	// Rule 1: Block deletion of Crust rules directory
	rules = append(rules, Rule{
		Name:        "block-crust-rules-dir-delete",
		Description: "Block deletion of Crust rules directory",
		Locked:      lockedTrue,
		Block: Block{
			Paths: []string{cfg.UserRulesDir + "/**"},
		},
		Actions:  []Operation{OpDelete},
		Message:  "Blocked: Crust rules directory is protected from deletion.",
		Severity: SeverityCritical,
		Source:   SourceBuiltin,
	})

	// Rule 2: Block writing to rules directory (except through API)
	rules = append(rules, Rule{
		Name:        "block-crust-rule-file-write",
		Description: "Block direct modification of rule files",
		Locked:      lockedTrue,
		Block: Block{
			Paths: []string{cfg.UserRulesDir + "/*.yaml"},
		},
		Actions:  []Operation{OpWrite},
		Message:  "Blocked: Crust rule files cannot be modified directly. Use the API.",
		Severity: SeverityCritical,
		Source:   SourceBuiltin,
	})

	// Rule 3: Block access to management API socket files
	rules = append(rules, Rule{
		Name:        "block-crust-socket-access",
		Description: "Block access to Crust management API sockets",
		Locked:      lockedTrue,
		Block: Block{
			Paths: []string{"**/.crust/crust-api-*.sock", "**/.crust/*.sock"},
		},
		Actions:  []Operation{OpRead, OpWrite, OpDelete},
		Message:  "Blocked: Crust management socket is protected.",
		Severity: SeverityCritical,
		Source:   SourceBuiltin,
	})

	return rules
}

// ReloadUserRules reloads rules from user directory.
// Integrity verification is performed inside LoadUser() using a read-once
// pattern: each file is read exactly once and the same bytes are used for
// both SHA3-256 checksum comparison and YAML parsing, eliminating any
// TOCTOU gap between integrity check and load.
func (e *Engine) ReloadUserRules() error {
	userRules, err := e.loader.LoadUser()
	if err != nil {
		return err
	}

	// Expand $HOME in user YAML rule paths
	userRules = expandRuleHomes(userRules, e.normalizer.GetHomeDir())

	compiled, err := e.compileRules(userRules, false)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.user = compiled
	e.rebuildMergedLocked()
	e.mu.Unlock()

	log.Info("Loaded %d user rules, total %d active rules", len(compiled), len(e.merged))

	// Notify reload callbacks
	e.notifyReload()

	return nil
}

// AddRulesFromFile adds rules from a file and reloads
func (e *Engine) AddRulesFromFile(path string) (string, error) {
	destPath, err := e.loader.AddRuleFile(path)
	if err != nil {
		return "", err
	}

	if err := e.ReloadUserRules(); err != nil {
		return destPath, err
	}

	return destPath, nil
}

// Evaluate evaluates a tool call through a 13-step pipeline (steps 0-12).
// Returns MatchResult indicating whether the call is allowed, blocked, or logged.
func (e *Engine) Evaluate(call ToolCall) MatchResult {
	// Step 0: Pre-checker (self-protection).
	if e.preChecker != nil {
		if m := e.preChecker(string(call.Arguments)); m != nil {
			return *m
		}
	}

	// Step 1: Sanitize tool name.
	call.Name = SanitizeToolName(call.Name)

	// Step 2: Extract paths and operation.
	info := e.extractor.Extract(call.Name, call.Arguments)

	// Steps 3-7: Content validation (Unicode, null bytes, obfuscation, evasion, DLP).
	if m := e.validateContent(&info); m != nil {
		return *m
	}

	// Steps 8-10: Path resolution (normalize, symlinks, hardcoded guards).
	allPaths, m := e.resolvePaths(info.Paths)
	if m != nil {
		return *m
	}

	// Steps 11-12: Rule matching (operation-based + content-only fallback).
	return e.matchRules(&info, allPaths, call.Name)
}

// validateContent runs content validation (steps 3-7): Unicode normalization,
// null byte blocking, obfuscation detection, evasion blocking, and DLP.
// Mutates info fields (Command, Content, RawJSON) via pointer.
func (e *Engine) validateContent(info *ExtractedInfo) *MatchResult {
	// Step 3: Normalize Unicode (NFKC + strip invisible) before any matching.
	if info.Command != "" {
		info.Command = NormalizeUnicode(info.Command)
	}
	if info.Content != "" {
		info.Content = NormalizeUnicode(info.Content)
	}
	if info.RawJSON != "" {
		info.RawJSON = NormalizeUnicode(info.RawJSON)
	}

	// Step 4: Block null bytes in write content.
	if (info.Operation == OpWrite || info.Operation == OpNone) && info.Content != "" {
		if strings.ContainsRune(info.Content, 0) {
			m := NewMatch("builtin:block-null-byte-write", SeverityHigh, ActionBlock, "Cannot write content containing null bytes")
			return &m
		}
	}

	// Step 5: PreFilter — detect obfuscation (base64, hex encoding).
	if info.Command != "" {
		if match := e.preFilter.Check(info.Command); match != nil {
			m := NewMatch("builtin:block-obfuscation", SeverityHigh, ActionBlock, fmt.Sprintf("Blocked: %s (%s)", match.Reason, match.PatternName))
			return &m
		}
	}

	// Step 6: Block evasive commands that prevent static analysis.
	if info.Evasive {
		m := NewMatch("builtin:block-shell-evasion", SeverityHigh, ActionBlock, info.EvasiveReason)
		return &m
	}

	// Step 7: DLP — detect API keys/tokens in all operations.
	dlpContent := info.RawJSON
	if dlpContent == "" {
		dlpContent = info.Content
	}
	return e.ScanDLP(dlpContent)
}

// resolvePaths runs path resolution (steps 8-10): prepare paths,
// resolve symlinks, and check hardcoded path guards.
func (e *Engine) resolvePaths(paths []string) ([]string, *MatchResult) {
	// Step 8: Prepare paths — filter bare shell globs, normalize, expand filesystem globs.
	normalizedPaths := e.normalizer.PreparePaths(paths)

	// Step 9: Resolve symlinks — match both original and resolved paths.
	resolvedPaths := e.normalizer.resolveSymlinks(normalizedPaths)
	allPaths := mergeUnique(normalizedPaths, resolvedPaths)

	// Step 10: Hardcoded path guards (after symlink resolution to catch symlink bypasses).
	if m := checkHardcodedPaths(allPaths); m != nil {
		return nil, m
	}

	return allPaths, nil
}

// getMergedRules returns the current merged rule set under read lock.
func (e *Engine) getMergedRules() []CompiledRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.merged
}

// matchRules evaluates operation-based and content-only rules (steps 11-12).
func (e *Engine) matchRules(info *ExtractedInfo, allPaths []string, toolName string) MatchResult {
	rules := e.getMergedRules()

	// Ensure Operations is populated — callers that build ExtractedInfo directly
	// (e.g., tests) may only set Operation without Operations.
	if info.Operation != OpNone && len(info.Operations) == 0 {
		info.Operations = []Operation{info.Operation}
	}

	// Step 11: Evaluate operation-based rules (for known tools).
	if info.Operation != OpNone {
		if result := e.evaluateOperationRules(rules, *info, allPaths, toolName); result.Matched {
			return result
		}
	}

	// Step 12: Fallback content-only rules — matches raw JSON of any tool.
	contentForRules := info.RawJSON
	if contentForRules == "" {
		contentForRules = info.Content
	}
	for _, compiled := range rules {
		if !compiled.Rule.IsEnabled() {
			continue
		}
		if compiled.Rule.IsContentOnly() && contentForRules != "" {
			// Respect actions filter; OpNone (unknown/MCP tools) always matches.
			if info.Operation != OpNone && !compiled.Rule.HasAnyAction(info.Operations) {
				continue
			}
			contentMatched := false
			if compiled.MatchCompiled != nil {
				if compiled.MatchCompiled.ContentRegex != nil {
					contentMatched = compiled.MatchCompiled.ContentRegex.MatchString(contentForRules)
				} else {
					contentMatched = containsIgnoreCase(contentForRules, compiled.MatchCompiled.Match.Content)
				}
			}
			if contentMatched {
				e.incrementHitCount(compiled.Rule.Name)
				return blockResult(&compiled.Rule, "")
			}
		}
	}

	return NoMatch()
}

// evaluateOperationRules evaluates operation-based rules (path, command, host matching)
func (e *Engine) evaluateOperationRules(rules []CompiledRule, info ExtractedInfo, normalizedPaths []string, toolName string) MatchResult {
	// Evaluate against rules (sorted by priority)
	for _, compiled := range rules {
		// Skip disabled rules
		if !compiled.Rule.IsEnabled() {
			continue
		}

		// Skip if rule doesn't apply to any of this command's operations
		if !compiled.Rule.HasAnyAction(info.Operations) {
			continue
		}

		// Check path matching for non-network operations (or network ops that also have paths)
		if compiled.PathMatcher != nil && len(normalizedPaths) > 0 {
			matched, matchedPath := compiled.PathMatcher.MatchAny(normalizedPaths)
			if matched {
				e.incrementHitCount(compiled.Rule.Name)
				return blockResult(&compiled.Rule, matchedPath)
			}
		}

		// Check host matching whenever hosts are extracted (not just OpNetwork).
		// This enables host rules to fire for scp (OpCopy), rsync, etc.
		// The HasAction check at the top of this loop still scopes correctly.
		if compiled.HostMatcher != nil && len(info.Hosts) > 0 {
			matched, matchedHost := compiled.HostMatcher.MatchAny(info.Hosts)
			if matched {
				e.incrementHitCount(compiled.Rule.Name)
				return blockResult(&compiled.Rule, matchedHost)
			}
		}

		// Evaluate advanced match conditions using pre-compiled patterns (Level 4+)
		if compiled.MatchCompiled != nil {
			if e.evaluateMatchCompiled(compiled.MatchCompiled, info, normalizedPaths, toolName) {
				e.incrementHitCount(compiled.Rule.Name)
				return blockResult(&compiled.Rule, "")
			}
		}

		// Evaluate AllConditions (AND logic - all conditions must match) using pre-compiled patterns
		if len(compiled.AllCompiledMatches) > 0 {
			allMatched := true
			for i := range compiled.AllCompiledMatches {
				if !e.evaluateMatchCompiled(&compiled.AllCompiledMatches[i], info, normalizedPaths, toolName) {
					allMatched = false
					break
				}
			}
			if allMatched {
				e.incrementHitCount(compiled.Rule.Name)
				return blockResult(&compiled.Rule, "")
			}
		}

		// Evaluate AnyConditions (OR logic - any condition matches) using pre-compiled patterns
		if len(compiled.AnyCompiledMatches) > 0 {
			for i := range compiled.AnyCompiledMatches {
				if e.evaluateMatchCompiled(&compiled.AnyCompiledMatches[i], info, normalizedPaths, toolName) {
					e.incrementHitCount(compiled.Rule.Name)
					return blockResult(&compiled.Rule, "")
				}
			}
		}
	}

	// No operation-based rule matched
	return NoMatch()
}

// evaluateMatchCompiled evaluates a single pre-compiled Match condition against the extracted info.
// Uses pre-compiled regex/glob patterns from CompiledMatch instead of re-compiling at runtime.
// Returns true only if ALL non-empty conditions in the Match are satisfied (AND within a single Match).
func (e *Engine) evaluateMatchCompiled(cm *CompiledMatch, info ExtractedInfo, normalizedPaths []string, toolName string) bool {
	if cm == nil {
		return true
	}

	// Path matching — use pre-compiled regex or glob
	if cm.Match.Path != "" {
		if !matchAnyRegexGlob(normalizedPaths, cm.PathRegex, cm.PathGlob, "") {
			return false
		}
	}

	// Command matching — use pre-compiled regex or literal substring
	if cm.Match.Command != "" {
		if info.Command == "" {
			return false
		}
		if cm.CommandRegex != nil {
			if !cm.CommandRegex.MatchString(info.Command) {
				return false
			}
		} else {
			if !containsIgnoreCase(info.Command, cm.Match.Command) {
				return false
			}
		}
	}

	// Host matching — use pre-compiled regex, glob, or literal
	if cm.Match.Host != "" {
		if !matchAnyRegexGlob(info.Hosts, cm.HostRegex, cm.HostGlob, cm.Match.Host) {
			return false
		}
	}

	// Content matching — use pre-compiled regex or literal substring
	if cm.Match.Content != "" {
		if info.Content == "" {
			return false
		}
		if cm.ContentRegex != nil {
			if !cm.ContentRegex.MatchString(info.Content) {
				return false
			}
		} else {
			// Literal match (case-insensitive substring)
			if !containsIgnoreCase(info.Content, cm.Match.Content) {
				return false
			}
		}
	}

	// Tool matching — just string comparison, no compilation needed
	if len(cm.Match.Tools) > 0 {
		if !matchTools(cm.Match.Tools, toolName) {
			return false
		}
	}

	// All non-empty conditions matched (or no conditions were set)
	return true
}

// evaluateMatch evaluates a single Match condition against the extracted info.
// Returns true only if ALL non-empty conditions in the Match are satisfied (AND within a single Match).
// maxRegexLen limits user-defined regex pattern length to bound compilation cost.
const maxRegexLen = 4096

// compileRegex compiles a regex with a length limit.
func compileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexLen {
		return nil, fmt.Errorf("regex pattern too long (%d > %d chars)", len(pattern), maxRegexLen)
	}
	return regexp.Compile(pattern)
}

// patternKind returns "regex" or "glob" based on the pattern prefix.
func patternKind(pattern string) string {
	if strings.HasPrefix(pattern, "re:") {
		return "regex"
	}
	return "glob"
}

// Glob separators used by compilePattern.
const (
	pathGlobSeparator rune = '/'
	hostGlobSeparator rune = '.'
)

// compilePattern compiles a pattern as either a regex (if "re:" prefixed) or a glob.
// The separator is used for glob compilation (pathGlobSeparator for paths, hostGlobSeparator for hosts).
func compilePattern(pattern string, separator rune) (*regexp.Regexp, glob.Glob, error) {
	if strings.HasPrefix(pattern, "re:") {
		re, err := compileRegex(pattern[3:])
		return re, nil, err
	}
	g, err := glob.Compile(pattern, separator)
	return nil, g, err
}

// matchAnyRegexGlob returns true if any item matches the regex, glob, or literal.
// Pass nil for unused matchers. Literal is only checked if both re and g are nil.
func matchAnyRegexGlob(items []string, re *regexp.Regexp, g glob.Glob, literal string) bool {
	for _, item := range items {
		if re != nil {
			if re.MatchString(item) {
				return true
			}
		} else if g != nil {
			if g.Match(item) {
				return true
			}
		} else if item == literal {
			return true
		}
	}
	return false
}

// matchTools checks if toolName (lowercase) is in the list of allowed tools
func matchTools(tools []string, toolName string) bool {
	toolLower := strings.ToLower(toolName)
	return slices.Contains(tools, toolLower)
}

// containsIgnoreCase checks if s contains substr (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// EvaluateJSON is a convenience method that accepts JSON arguments
func (e *Engine) EvaluateJSON(toolName string, argsJSON string) MatchResult {
	return e.Evaluate(ToolCall{
		Name:      toolName,
		Arguments: json.RawMessage(argsJSON),
	})
}

// blockResult creates a MatchResult for a blocking rule match.
// If matchedValue is non-empty, {path} and {host} placeholders in the message are expanded.
func blockResult(rule *Rule, matchedValue string) MatchResult {
	msg := rule.Message
	if matchedValue != "" {
		msg = strings.Replace(msg, "{path}", matchedValue, 1)
		msg = strings.Replace(msg, "{host}", matchedValue, 1)
	}
	return NewMatch(rule.Name, rule.GetSeverity(), ActionBlock, msg)
}

// GetRules returns all active rules
func (e *Engine) GetRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]Rule, len(e.merged))
	for i, cr := range e.merged {
		rule := cr.Rule
		// Update hit count from stats
		if count := e.hitCounts[rule.Name]; count != nil {
			rule.HitCount = atomic.LoadInt64(count)
		}
		rules[i] = rule
	}
	return rules
}

// GetBuiltinRules returns only builtin rules
func (e *Engine) GetBuiltinRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return extractRules(e.builtin)
}

// GetUserRules returns only user rules
func (e *Engine) GetUserRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return extractRules(e.user)
}

// extractRules converts a slice of CompiledRule to a slice of Rule.
func extractRules(compiled []CompiledRule) []Rule {
	rules := make([]Rule, len(compiled))
	for i, cr := range compiled {
		rules[i] = cr.Rule
	}
	return rules
}

// RuleCount returns total number of active rules
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.merged)
}

// LockedRuleCount returns the number of locked builtin rules
func (e *Engine) LockedRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	count := 0
	for _, cr := range e.builtin {
		if cr.Rule.IsLocked() {
			count++
		}
	}
	return count
}

// CountLockedBuiltinRules returns the total number of locked builtin rules
// (YAML + dynamic) without requiring a full Engine instance.
func CountLockedBuiltinRules() int {
	loader := NewLoader("")
	yamlRules, err := loader.LoadBuiltin()
	if err != nil {
		return 0
	}
	dynamic := generateProtectionRules(EngineConfig{UserRulesDir: DefaultUserRulesDir()})
	count := len(dynamic) // all dynamic rules are locked
	for _, r := range yamlRules {
		if r.IsLocked() {
			count++
		}
	}
	return count
}

// Close releases resources held by the engine (e.g. the PowerShell worker
// pool). It is safe to call concurrently and multiple times.
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		if e.extractor != nil {
			e.extractor.Close()
		}
	})
}

// GetLoader returns the rule loader
func (e *Engine) GetLoader() *Loader {
	return e.loader
}

// ScanDLP runs DLP (Data Loss Prevention) patterns against content.
// Returns a non-nil MatchResult if a secret is detected, nil if clean.
// This is used by PipeInspect to scan server responses for leaked secrets.
func (e *Engine) ScanDLP(content string) *MatchResult {
	if content == "" {
		return nil
	}
	// Tier 1: hardcoded patterns (fast, always available)
	for _, pat := range dlpPatterns {
		if pat.re.MatchString(content) {
			m := NewMatch(pat.name, SeverityCritical, ActionBlock, pat.message)
			return &m
		}
	}
	// Tier 2: crypto-specific DLP (checksum-validated)
	if m := scanCrypto(content); m != nil {
		r := NewMatch(m.name, SeverityCritical, ActionBlock, m.message)
		return &r
	}
	// Tier 3: gitleaks (if available)
	if findings := e.dlpScanner.Scan(content); len(findings) > 0 {
		f := findings[0]
		msg := "Blocked secret — " + f.Description
		if len(findings) > 1 {
			msg += fmt.Sprintf(" (and %d more)", len(findings)-1)
		}
		r := NewMatch("builtin:dlp-gitleaks-"+f.RuleID, SeverityHigh, ActionBlock, msg)
		return &r
	}
	return nil
}

// RuleValidationResult holds per-rule validation results.
type RuleValidationResult struct {
	Name  string `json:"name"`
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// ValidateYAMLFull validates YAML content including pattern compilation.
// Returns per-rule validation results so callers can report all errors, not just the first.
func (e *Engine) ValidateYAMLFull(data []byte) ([]RuleValidationResult, error) {
	rules, err := e.loader.parseRuleSet(data, "inline", SourceCLI)
	if err != nil {
		return nil, err
	}

	results := make([]RuleValidationResult, 0, len(rules))
	for _, rule := range rules {
		result := RuleValidationResult{Name: rule.Name, Valid: true}
		if _, err := compileOneRule(rule); err != nil {
			result.Valid = false
			result.Error = err.Error()
		}
		results = append(results, result)
	}
	return results, nil
}

// GetAllRules returns all rules (builtin + user) as a flat slice.
// Useful for bulk operations like linting and export.
func (e *Engine) GetAllRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]Rule, 0, len(e.builtin)+len(e.user))
	for _, cr := range e.builtin {
		rules = append(rules, cr.Rule)
	}
	for _, cr := range e.user {
		rules = append(rules, cr.Rule)
	}
	return rules
}

// GetCompiledRules returns all compiled rules (for inspection/debugging)
func (e *Engine) GetCompiledRules() []CompiledRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]CompiledRule, len(e.merged))
	copy(out, e.merged)
	return out
}

// OnReload registers a callback to be called after rules are reloaded.
// The callback receives the complete list of all rules (builtin + user).
func (e *Engine) OnReload(callback ReloadCallback) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onReloadCallbacks = append(e.onReloadCallbacks, callback)
}

// notifyReload calls all registered reload callbacks.
func (e *Engine) notifyReload() {
	rules := e.GetAllRules()
	e.mu.RLock()
	cbs := make([]ReloadCallback, len(e.onReloadCallbacks))
	copy(cbs, e.onReloadCallbacks)
	e.mu.RUnlock()
	for _, cb := range cbs {
		go cb(rules) // Non-blocking
	}
}

// sanitizePattern rejects patterns containing null bytes or control characters.
// Returns an error so the user gets a clear message about what's wrong.
func sanitizePattern(pattern string) error {
	for i := range len(pattern) {
		if pattern[i] == 0 {
			return fmt.Errorf("pattern contains null byte at position %d", i)
		}
		if pattern[i] < 0x20 && pattern[i] != '\t' {
			return fmt.Errorf("pattern contains control character 0x%02x at position %d", pattern[i], i)
		}
	}
	return nil
}

// sanitizePatterns validates a slice of patterns, returning a contextual error.
func sanitizePatterns(patterns []string, ruleName, fieldName string) error {
	for i, p := range patterns {
		if err := sanitizePattern(p); err != nil {
			return fmt.Errorf("rule %q %s[%d]: %w", ruleName, fieldName, i, err)
		}
	}
	return nil
}

// compileMatchConditions compiles a slice of Match conditions into CompiledMatch values.
func compileMatchConditions(conditions []Match, ruleName, condType string) ([]CompiledMatch, error) {
	var compiled []CompiledMatch
	for i, cond := range conditions {
		cm, err := compileMatchPattern(&cond)
		if err != nil {
			return nil, fmt.Errorf("rule %q %s[%d]: %w", ruleName, condType, i, err)
		}
		if cm != nil {
			compiled = append(compiled, *cm)
		}
	}
	return compiled, nil
}

// compileMatchPattern pre-compiles a single Match condition's patterns.
// Returns clear errors for invalid patterns so rules are rejected at insert time.
func compileMatchPattern(m *Match) (*CompiledMatch, error) {
	if m == nil {
		return nil, nil
	}
	cm := &CompiledMatch{Match: *m}

	// Sanitize all pattern fields
	for _, check := range []struct{ name, pattern string }{
		{"path", m.Path}, {"command", m.Command},
		{"host", m.Host}, {"content", m.Content},
	} {
		if check.pattern == "" {
			continue
		}
		if err := sanitizePattern(check.pattern); err != nil {
			return nil, fmt.Errorf("match.%s: %w", check.name, err)
		}
	}

	// Compile Path (regex or glob)
	if m.Path != "" {
		re, g, err := compilePattern(m.Path, pathGlobSeparator)
		if err != nil {
			return nil, fmt.Errorf("match.path %s %q: %w", patternKind(m.Path), m.Path, err)
		}
		cm.PathRegex, cm.PathGlob = re, g
	}

	// Compile Command (regex only; literals use substring match at runtime)
	if m.Command != "" && strings.HasPrefix(m.Command, "re:") {
		re, err := compileRegex(m.Command[3:])
		if err != nil {
			return nil, fmt.Errorf("match.command regex %q: %w", m.Command, err)
		}
		cm.CommandRegex = re
	}

	// Compile Host (regex or glob)
	if m.Host != "" {
		re, g, err := compilePattern(m.Host, hostGlobSeparator)
		if err != nil {
			return nil, fmt.Errorf("match.host %s %q: %w", patternKind(m.Host), m.Host, err)
		}
		cm.HostRegex, cm.HostGlob = re, g
	}

	// Compile Content (regex only; literals use substring match at runtime)
	if m.Content != "" && strings.HasPrefix(m.Content, "re:") {
		re, err := compileRegex(m.Content[3:])
		if err != nil {
			return nil, fmt.Errorf("match.content regex %q: %w", m.Content, err)
		}
		cm.ContentRegex = re
	}

	return cm, nil
}

// compileRules compiles path/host patterns in rules.
// When strict is true (builtin rules), any compilation error aborts the entire batch.
// When strict is false (user rules), bad rules are skipped with a warning.
func (e *Engine) compileRules(rules []Rule, strict bool) ([]CompiledRule, error) {
	compiled := make([]CompiledRule, 0, len(rules))

	for _, rule := range rules {
		if !rule.IsEnabled() {
			continue
		}

		cr, err := compileOneRule(rule)
		if err != nil {
			if strict {
				return nil, err
			}
			log.Warn("Skipping rule %q from %s: %v", rule.Name, rule.FilePath, err)
			continue
		}
		compiled = append(compiled, cr)
	}

	return compiled, nil
}

// compileOneRule validates and compiles a single rule's patterns.
// Returns a clear error if any pattern is invalid.
func compileOneRule(rule Rule) (CompiledRule, error) {
	// Sanitize Block patterns before compilation
	for _, check := range []struct {
		patterns []string
		field    string
	}{
		{rule.Block.Paths, "block.paths"},
		{rule.Block.Except, "block.except"},
		{rule.Block.Hosts, "block.hosts"},
	} {
		if err := sanitizePatterns(check.patterns, rule.Name, check.field); err != nil {
			return CompiledRule{}, err
		}
	}

	// Compile path matcher (Block.Paths/Except)
	var pathMatcher *Matcher
	if len(rule.Block.Paths) > 0 {
		var err error
		pathMatcher, err = NewMatcher(rule.Block.Paths, rule.Block.Except)
		if err != nil {
			return CompiledRule{}, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
	}

	// Compile host matcher (Block.Hosts)
	var hostMatcher *Matcher
	if len(rule.Block.Hosts) > 0 {
		var err error
		hostMatcher, err = NewMatcher(rule.Block.Hosts, nil)
		if err != nil {
			return CompiledRule{}, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
	}

	// Compile Match patterns (Level 4+ rules)
	var matchCompiled *CompiledMatch
	if rule.Match != nil {
		var err error
		matchCompiled, err = compileMatchPattern(rule.Match)
		if err != nil {
			return CompiledRule{}, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
	}

	// Compile AllConditions (AND logic) and AnyConditions (OR logic)
	allCompiled, err := compileMatchConditions(rule.AllConditions, rule.Name, "all")
	if err != nil {
		return CompiledRule{}, err
	}
	anyCompiled, err := compileMatchConditions(rule.AnyConditions, rule.Name, "any")
	if err != nil {
		return CompiledRule{}, err
	}

	return CompiledRule{
		Rule:               rule,
		PathMatcher:        pathMatcher,
		HostMatcher:        hostMatcher,
		MatchCompiled:      matchCompiled,
		AllCompiledMatches: allCompiled,
		AnyCompiledMatches: anyCompiled,
	}, nil
}

// rebuildMergedLocked rebuilds the merged rule list (must hold write lock)
func (e *Engine) rebuildMergedLocked() {
	// Combine builtin and user rules
	all := make([]CompiledRule, 0, len(e.builtin)+len(e.user))
	all = append(all, e.builtin...)
	all = append(all, e.user...)

	// Sort by priority (lower = higher priority)
	slices.SortFunc(all, func(a, b CompiledRule) int {
		return cmp.Compare(a.Rule.GetPriority(), b.Rule.GetPriority())
	})

	e.merged = all

	// Initialize hit counts for new rules
	for _, cr := range all {
		if _, exists := e.hitCounts[cr.Rule.Name]; !exists {
			var count int64
			e.hitCounts[cr.Rule.Name] = &count
		}
	}
}

// mergeUnique returns the union of two string slices, preserving order and
// removing duplicates. Used to combine pre-symlink and post-symlink resolved
// paths so that rule patterns match against both forms.
func mergeUnique(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a))
	result := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// incrementHitCount increments the hit count for a rule.
// Acquires RLock to safely read the hitCounts map, which may be written
// by rebuildMergedLocked during concurrent ReloadUserRules.
func (e *Engine) incrementHitCount(name string) {
	e.mu.RLock()
	count := e.hitCounts[name]
	e.mu.RUnlock()
	if count != nil {
		atomic.AddInt64(count, 1)
	}
}
