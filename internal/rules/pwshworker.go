package rules

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"sync"
	"unicode/utf16"
)

// psBootstrapScript is the PowerShell script embedded in the pwsh worker process.
// It runs in a loop, reading JSON requests from stdin and writing JSON responses
// to stdout. Each request contains a PS command string; each response contains
// the parsed commands (name + args) and any parse errors.
//
// The script uses the native PS AST API for accurate parsing:
//   - [System.Management.Automation.Language.Parser]::ParseInput() — real PS parser
//   - AssignmentStatementAst tracking — resolves simple $var = "value" assignments
//   - CommandAst extraction — yields command names and their string arguments
//
// Supported platforms: Windows 10/11 (powershell.exe 5.1 always present;
// pwsh.exe 7+ used when available).
const psBootstrapScript = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
# 'Stop' ensures all errors propagate to the outer catch block, which always
# writes a JSON response — preventing scanner.Scan() from blocking indefinitely
# on the Go side if a runtime error occurs without producing output.
$ErrorActionPreference = 'Stop'

while ($true) {
    $ln = [Console]::In.ReadLine()
    if ($null -eq $ln) { break }
    try {
        $req  = $ln | ConvertFrom-Json
        $errs = [System.Management.Automation.Language.ParseError[]]@()
        $toks = [System.Management.Automation.Language.Token[]]@()
        $ast  = [System.Management.Automation.Language.Parser]::ParseInput(
                    $req.command, [ref]$toks, [ref]$errs)

        # Walk top-level statements in source order via $block.Statements.
        # For each statement: record any direct $var = "literal" assignment
        # FIRST, then extract all CommandAst nodes from that statement.
        #
        # This is the correct scoping approach:
        #   $p = "secret"; Get-Content $p   → $p resolved (assignment precedes use)
        #   ForEach-Object { $p = "x" }; Get-Content $p → $p NOT resolved
        #     (inner-scope assignments never pollute the top-level $vars table)
        #
        # FindAll($pred, $false) on a ScriptBlockAst root skips its own children
        # due to PS visitor behavior, so we avoid it for assignment collection and
        # instead walk $block.Statements directly.
        $vars = @{}
        $cmds = [System.Collections.Generic.List[object]]::new()
        foreach ($block in @($ast.BeginBlock, $ast.ProcessBlock, $ast.EndBlock)) {
            if ($null -eq $block) { continue }
            foreach ($stmt in $block.Statements) {
                # Record direct-scope $var = "literal" before processing this statement's commands.
                # AssignmentStatementAst.Right is a CommandExpressionAst (not PipelineAst);
                # navigate Right.Expression to reach the StringConstantExpressionAst value.
                if ($stmt -is [System.Management.Automation.Language.AssignmentStatementAst]) {
                    try {
                        $lhs = $stmt.Left
                        $rhs = $stmt.Right
                        if ($lhs -is [System.Management.Automation.Language.VariableExpressionAst] -and
                            $rhs -is [System.Management.Automation.Language.CommandExpressionAst] -and
                            $rhs.Expression -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                            $vars[$lhs.VariablePath.UserPath] = $rhs.Expression.Value
                        }
                    } catch { $null = $_ }
                }
                # Extract all CommandAst nodes from this statement, recursing into
                # nested scriptblocks (pipelines, foreach bodies, etc.).
                # Called on $stmt (a StatementAst), not the root ScriptBlockAst,
                # so FindAll with $true works correctly.
                $stmt.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.CommandAst]
                }, $true) | ForEach-Object {
                    $nm = $_.GetCommandName()
                    if ($nm) {  # filters both $null and "" (e.g. & "" arg)
                        $ag = [System.Collections.Generic.List[string]]::new()
                        $_.CommandElements | Select-Object -Skip 1 | ForEach-Object {
                            try {
                                if ($_ -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                                    $ag.Add($_.Value)
                                } elseif ($_ -is [System.Management.Automation.Language.VariableExpressionAst]) {
                                    $k = $_.VariablePath.UserPath
                                    if ($vars.ContainsKey($k)) { $ag.Add($vars[$k]) }
                                } elseif ($_ -is [System.Management.Automation.Language.CommandParameterAst]) {
                                    $ag.Add('-' + $_.ParameterName)
                                    # -Flag:value colon syntax: Argument holds the value expression.
                                    if ($null -ne $_.Argument) {
                                        if ($_.Argument -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                                            $ag.Add($_.Argument.Value)
                                        } elseif ($_.Argument -is [System.Management.Automation.Language.VariableExpressionAst]) {
                                            $k = $_.Argument.VariablePath.UserPath
                                            if ($vars.ContainsKey($k)) { $ag.Add($vars[$k]) }
                                        }
                                    }
                                }
                            } catch { $null = $_ }
                        }
                        $cmds.Add([PSCustomObject]@{
                            name = $nm
                            args = [string[]]$ag.ToArray()
                        })
                    }
                }
            }
        }

        $resp = [PSCustomObject]@{
            commands    = [object[]]$cmds.ToArray()
            parseErrors = [string[]]@($errs | ForEach-Object { $_.Message })
        }
        # Strip all newlines: ConvertTo-Json -Compress is not guaranteed to
        # produce a single line in Windows PowerShell 5.1 with nested objects.
        # The Go side uses bufio.Scanner which reads one line at a time, so
        # the response MUST be exactly one line.
        # Use -replace with single-quoted regex (no PS backtick escapes needed,
        # which would conflict with Go raw string literal delimiters).
        ($resp | ConvertTo-Json -Compress -Depth 5) -replace '\r\n|\r|\n', ''
        [Console]::Out.Flush()
    } catch {
        ([PSCustomObject]@{
            commands    = [object[]]@()
            parseErrors = [string[]]@($_.Exception.Message)
        } | ConvertTo-Json -Compress) -replace '\r\n|\r|\n', ''
        [Console]::Out.Flush()
    }
}
`

// pwshWorkerRequest is the IPC request sent from Go → pwsh worker.
type pwshWorkerRequest struct {
	Command string `json:"command"`
}

// pwshWorkerResponse is the IPC response received from pwsh worker → Go.
// Commands uses []parsedCommand so results plug directly into
// extractFromParsedCommandsDepth without conversion.
type pwshWorkerResponse struct {
	Commands    []parsedCommand `json:"commands"`
	ParseErrors []string        `json:"parseErrors"`
}

// pwshWorker manages a persistent pwsh subprocess for accurate PowerShell
// command analysis. It mirrors the shellWorker pattern: JSON over stdin/stdout,
// auto-restart on crash, mutex-serialized access.
type pwshWorker struct {
	mu       sync.Mutex
	proc     *exec.Cmd
	stdin    io.WriteCloser
	scanner  *bufio.Scanner
	encoder  *json.Encoder // reused across parse() calls to avoid per-call allocation
	pwshPath string        // path to pwsh.exe or powershell.exe
	encoded  string        // base64 UTF-16LE encoded bootstrap script
}

// FindPwsh returns the path to pwsh.exe or powershell.exe, preferring the
// newer pwsh (PowerShell 7+) over legacy powershell (Windows PowerShell 5.1).
// On supported Windows 10/11 systems, powershell.exe is always present so
// this should always succeed.
func FindPwsh() (string, bool) {
	for _, name := range []string{"pwsh.exe", "powershell.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, true
		}
	}
	return "", false
}

// newPwshWorker creates and starts a pwsh worker subprocess.
func newPwshWorker(pwshPath string) (*pwshWorker, error) {
	w := &pwshWorker{
		pwshPath: pwshPath,
		encoded:  encodePSCommand(psBootstrapScript),
	}
	if err := w.start(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *pwshWorker) start() error {
	proc := exec.CommandContext(context.Background(), w.pwshPath, //nolint:gosec // pwshPath comes from exec.LookPath, not user input
		"-NoProfile", "-NonInteractive", "-EncodedCommand", w.encoded)
	stdin, err := proc.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := proc.StdoutPipe()
	if err != nil {
		stdin.Close()
		return err
	}
	proc.Stderr = io.Discard

	if err := proc.Start(); err != nil {
		stdin.Close()
		return err
	}

	w.proc = proc
	w.stdin = stdin
	w.encoder = json.NewEncoder(stdin)
	w.scanner = bufio.NewScanner(stdout)
	w.scanner.Buffer(make([]byte, 1<<20), 1<<20)
	return nil
}

// parse sends a command to the pwsh worker and returns the parsed result.
// Returns an error if the worker died or the response was malformed; the
// worker is automatically restarted on the next call.
func (w *pwshWorker) parse(cmd string) (pwshWorkerResponse, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.proc == nil {
		if err := w.start(); err != nil {
			return pwshWorkerResponse{}, err
		}
	}

	if err := w.encoder.Encode(pwshWorkerRequest{Command: cmd}); err != nil {
		w.kill()
		return pwshWorkerResponse{}, err
	}

	if !w.scanner.Scan() {
		w.kill()
		return pwshWorkerResponse{}, errors.New("pwsh worker: unexpected EOF")
	}

	var resp pwshWorkerResponse
	if err := json.Unmarshal(w.scanner.Bytes(), &resp); err != nil {
		w.kill()
		return pwshWorkerResponse{}, err
	}

	return resp, nil
}

func (w *pwshWorker) kill() {
	if w.stdin != nil {
		w.stdin.Close() // close write end before Kill to avoid fd leak
	}
	if w.proc != nil && w.proc.Process != nil {
		w.proc.Process.Kill()
		proc := w.proc
		go proc.Wait() // async reap; error irrelevant after Kill()
	}
	w.proc = nil
	w.stdin = nil
	w.encoder = nil
	w.scanner = nil
}

func (w *pwshWorker) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.kill() // kill() closes stdin before sending SIGKILL
}

// encodePSCommand encodes a PowerShell script as base64 UTF-16LE for use
// with pwsh -EncodedCommand. PowerShell expects little-endian UTF-16.
func encodePSCommand(s string) string {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(buf)
}
