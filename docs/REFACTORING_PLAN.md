# Crust Refactoring Plan

Systematically verified against codebase on 2026-03-08. All findings confirmed with file paths and line numbers.

## P0 — Must Fix (Security)

### P0-1: Replace panics with error returns in security paths

**Problem:** 5 panics in production code crash the entire proxy on unknown APIType. All confirmed in security-critical request/response paths.

| # | File | Line | Panic Message |
|---|------|------|---------------|
| 1 | `internal/security/interceptor.go` | 246 | `panic("unhandled types.APIType: " + ...)` |
| 2 | `internal/httpproxy/sse_buffer.go` | 348 | `panic("unhandled types.APIType: " + ...)` |
| 3 | `internal/httpproxy/sse_buffer.go` | 501 | `panic("unhandled types.APIType: " + ...)` |
| 4 | `internal/httpproxy/sse_parser.go` | 296 | `panic("unhandled types.APIType: " + ...)` |
| 5 | `internal/rules/dlp_crypto.go` | 68  | `panic("bip39: cannot read embedded ...")` |

**Fix:** Replace panics #1-4 with error returns. For #5 (init with embedded FS), keep as-is — truly unreachable unless binary is corrupted.

**Effort:** S (1 day)

### P0-2: Add `go generate` drift check to CI

**Problem:** `go generate ./...` not run in CI. Schema files can drift from Go types without detection.

**Fix:** Already done — added `go generate ./... && git diff --exit-code` to lint job.

**Status:** DONE

### P0-3: Add rule-coverage check to CI

**Problem:** `scripts/check-rule-coverage.sh` only runs locally via pre-commit.

**Fix:** Already done — added to lint job.

**Status:** DONE

### P0-4: Add docker-test timeout

**Problem:** docker-test job has no timeout-minutes, can hang indefinitely.

**Fix:** Already done — added `timeout-minutes: 15`.

**Status:** DONE

---

## P1 — Should Fix

### P1-1: Extract shared schema-check library

**Problem:** `internal/rules/cmd/schema-check/main.go` (322 lines) and `internal/plugin/cmd/schema-check/main.go` (427 lines) share ~200 lines of nearly identical code: `mapKeys()`, `structFields()`, error collection, output generation.

**Fix:** Create `internal/schemacheck/` package with shared helpers:
- `ParseSchema(path) (*SchemaDoc, error)`
- `ExtractStructFields(dir, name, tagName) (map[string]bool, error)` — parameterize yaml vs json tag
- `ExtractMapKeys(dir, varName) ([]string, error)`
- `ExtractConstValues(dir, names) ([]string, error)`

Both tools import and call these. ~200 lines removed, ~100 lines added = net -100 lines.

**Effort:** M (2-3 days)

### ~~P1-2: Deduplicate APIType switch statements~~

**Status:** CLOSED — panics replaced in P0-1. Remaining switches have different return
types across packages; a generic helper adds complexity without value. The `exhaustive`
linter already catches missing cases at compile time.

### P1-3: Add `RuleEvaluator` interface

**Problem:** No evaluator interface exists (verified by grep). `security.Interceptor` and `httpproxy.Proxy` depend directly on `*rules.Engine`, making them untestable without a full engine.

**Fix:** Define consumer-side interface:
```go
// In internal/security/ or a shared package:
type RuleEvaluator interface {
    Evaluate(ctx context.Context, input EvalInput) *EvalResult
}
```

Inject into `Interceptor` and proxy instead of `*rules.Engine`.

**Effort:** M (2-3 days)

### P1-4: Split `extractor.go` (3568 lines)

**Problem:** Single file handles shell parsing, PowerShell, network commands, file operations, evasion detection — all in one monolith.

**Fix:** Split by domain:
- `extractor.go` — core CommandInfo type, main extraction logic
- `extractor_shell.go` — bash/sh command parsing
- `extractor_net.go` — network command extraction (curl, wget, etc.)
- `extractor_file.go` — file operation extraction (cp, mv, rm, etc.)
- `extractor_evasion.go` — evasion detection (base64, hex, obfuscation)

Same package, just file organization. No API changes.

**Effort:** M (2-3 days)

### P1-5: Split `engine.go` (1210 lines)

**Problem:** Engine handles compilation, matching, DLP, hot-reload, and statistics all in one file.

**Fix:** Extract:
- `compiler.go` — rule compilation (CompiledRule, CompiledMatch)
- Keep `engine.go` as orchestrator (Evaluate, lifecycle)

Unexport `CompiledMatch` and `CompiledRule` (verified: only used within rules package).

**Effort:** M (1-2 days)

### P1-6: Remove global singletons

**Problem:** `globalEngine` (engine.go:136) and `globalManager` (manager.go:38) are module-level globals with RWMutex guards. Makes testing harder and hides dependencies.

**Fix:** Dependency injection from `main.go`. Pass `*Engine` and `*Manager` to constructors instead of using `GetGlobalEngine()`.

**Effort:** L (3-5 days, wide blast radius)

### P1-7: Add gitleaks to CI

**Problem:** Secret scanning only runs locally via pre-commit. If developer skips hooks, secrets can leak.

**Fix:** Add `gitleaks/gitleaks-action@v2` to lint or security job.

**Effort:** S (30 min)

---

## P2 — Nice to Have

### P2-1: Split `proxy.go` (1265 lines)
Extract request/response handling from rule evaluation. **Effort:** M

### P2-2: Split `storage.go` (894 lines)
Split into db.go, encryption.go, schema.go. **Effort:** M

### P2-3: Standardize Close/Shutdown naming
Engine uses `Close()`, Manager uses `Shutdown(ctx)`. Pick one pattern. **Effort:** S

### P2-4: Add benchmark CI
Run `scripts/bench.sh --quick` on PRs. Detect performance regressions. **Effort:** S

### P2-5: Add semgrep SAST to CI
Currently pre-push only. Add to security job for PR coverage. **Effort:** S

### P2-6: Move magic constants to config
`maxSocketPathLen=104`, `maxRequestBody=100MB`, `DefaultPoolSize=8` etc. scattered in code. Centralize. **Effort:** S

### P2-7: Unexport package-internal types
`CompiledMatch`, `CompiledRule` (rules), `RequestBody` (httpproxy) — exported but only used internally. **Effort:** S

---

## Verified Non-Issues (No Action Needed)

| Finding | Verification Result | Decision |
|---------|-------------------|----------|
| acpwrap vs autowrap duplication | Intentionally separate; autowrap delegates to acpwrap | No merge |
| Path normalization overlap | normalizer.go delegates to pathutil.go by design | No change |
| TUI severity functions accept `string` | Intentional — handles both `rules.Severity` and `LintSeverity` | No change |
| ValidOperations/ValidSeverities runtime maps | Necessary for YAML-sourced input validation | No change |
| dlp_crypto.go init() panic | Embedded FS, unreachable unless binary corrupted | No change |

---

## Recommended Execution Order

**Phase 1 (1 week):** P0-1 + P1-2 (panics → error returns + APIType dispatch helper)
**Phase 2 (1 week):** P1-1 + P1-7 + P2-4 + P2-5 (schema dedup, CI hardening)
**Phase 3 (2 weeks):** P1-3 + P1-4 + P1-5 (interfaces, file splits)
**Phase 4 (2 weeks):** P1-6 + P2-1 + P2-2 (DI refactor, proxy/storage splits)
**Phase 5 (ongoing):** P2-3, P2-6, P2-7 (cleanup)
