# Shell Command Parsing Workflow

The extractor processes Bash tool calls through a multi-stage pipeline that combines AST analysis with interpreter dry-run for accurate path extraction.

Source: `internal/rules/extractor.go`

## Pipeline

```text
extractBashCommand (entry point)
 │
 ├─ A. Collect command strings from all knownCommandFields
 │     (command, cmd, script, shell_command, shell)
 │
 └─ B. For each command string:
      │
      ├─ 1. IsSuspiciousInput(raw cmd)
      │     Checks BEFORE parsing — AST printer strips null bytes
      │     and normalizes control chars, so post-parse checks miss evasion.
      │
      ├─ 2. syntax.Parse → AST
      │
      ├─ 3. syntax.Simplify
      │     Strips redundant parens, unnecessary quotes, duplicate subshells.
      │
      ├─ 4. minPrinter.Print(AST) → info.Command
      │     Canonical minified string for match.command rule matching.
      │     Captures full syntax including non-executed branches (e.g.,
      │     "false && rm -rf /" is visible even though Runner skips rm).
      │
      └─ 5. runShellFile(AST) → []parsedCommand, symtab
           │  interp.Runner in dry-run mode:
           │  - CallHandler: captures all commands (builtins + externals)
           │  - ExecHandler: no-op (prevents actual execution)
           │  - OpenHandler: captures redirect paths (fires before CallHandler)
           │  - ReadDirHandler2/StatHandler: disabled (no filesystem access)
           │  - Env seeded with process env + parent symtab
           │
           └─ extractFromParsedCommandsDepth (semantic extraction)
                For each parsedCommand:
                ├─ Mark evasive if HasSubst ($() or backticks)
                ├─ resolveCommand: strip wrappers (sudo, env, timeout...)
                ├─ Shell interpreter + -c flag → recursive parseShellCommandsExpand
                ├─ Command DB lookup → extract paths by positional index / flags
                ├─ Interpreter code flags (python -c, perl -e) → regex path extraction
                └─ Redirect paths → info.Paths (write for >/>>; read for <)
```

## Why two views

The pipeline produces two representations of the same command, serving different security purposes:

- **minPrint** (step 4): Conservative full-syntax view for `match.command` rules. Captures intent — including commands in non-executed branches like `false && rm -rf /`. Used for rule matching and pre-filter.

- **Runner** (step 5): Execution-path view for path extraction. Only captures commands that would actually execute, with variables fully expanded. Used to populate `info.Paths`, `info.Hosts`, and `info.Operation`.

Eliminating minPrint in favor of reconstructing `info.Command` from Runner output would create a detection gap: commands behind short-circuited `&&`/`||` would become invisible to `match.command` rules.

## Key types

| Type | Purpose |
|------|---------|
| `ExtractedInfo` | Output: paths, hosts, operation, command string, evasion flags |
| `parsedCommand` | Intermediate: single command with name, args, redirect paths, subst flag |
| `CommandInfo` | Config: maps command names to operations and path argument positions |

## Recursion

`sh -c`, `bash -c`, etc. trigger recursive parsing up to `maxShellRecursionDepth` (3). The parent's symbol table propagates to the child via `mergeEnvArgs` + `parseShellCommandsExpand`, so `env F=/etc/passwd sh -c 'cat $F'` correctly extracts `/etc/passwd`.

## Environment

The Runner is seeded with the real process environment (`os.Environ()`) so variables like `$HOME` resolve to actual values at extraction time. For testing, `NewExtractorWithEnv` accepts a custom environment map.

## PowerShell (Windows 10/11)

On Windows 10/11, `Bash` tool calls may contain PowerShell commands. The bash parser handles many PS cmdlets correctly (they look like POSIX commands), but fails on PS-specific syntax: `$var="value"` assignments, `C:\path\with\backslashes`, and `\\UNC\paths`.

Crust uses a **dual-parse** strategy on Windows:

```text
extractBashCommand (Windows path)
 │
 ├─ 1. looksLikePowerShell? (psVarAssignRe / PS cmdlet names)
 │
 ├─ 2. syntax.Parse (bash AST)
 │     ├─ Success → extract paths via Runner (step 5 above)
 │     │             + if looksLikePowerShell: pwsh worker augments results
 │     │
 │     └─ Failure → pwsh worker as authoritative PS parser
 │                   ├─ PS parse OK → extract from PS AST
 │                   └─ PS parse error / crash → Evasive = true
 │
 └─ 3. Results merged: paths/hosts union, highest-severity operation wins
```

**pwsh worker** (`pwshworker.go`): a persistent `pwsh.exe` (PS 7+, preferred) or `powershell.exe` (5.1, always present on Windows 10/11) subprocess. The bootstrap script uses `[System.Management.Automation.Language.Parser]::ParseInput()` — a pure AST parser, never executes commands. JSON over stdin/stdout; auto-restarts on crash.

**Fallback** (no pwsh worker): heuristic `substitutePSVariables` + `normalizePSBackslashPaths` pre-processing before bash parsing, gated behind `runtime.GOOS == "windows"`.

**Evasion**: a PS-looking command that crashes the worker subprocess is blocked as evasive (fail-closed). A command with PS parse errors but valid bash syntax is allowed — bash extraction stands.
