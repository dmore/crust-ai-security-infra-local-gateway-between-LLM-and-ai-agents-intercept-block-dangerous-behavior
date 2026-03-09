package rules

import (
	"encoding/json"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/BakeLens/crust/internal/pathutil"
	"github.com/BakeLens/crust/internal/rules/pwsh"
)

// ExtractedInfo contains paths and operation from a tool call
type ExtractedInfo struct {
	Operation     Operation   // highest-priority operation (kept for backward compat)
	Operations    []Operation // all operations this command performs (deduplicated)
	Paths         []string
	Hosts         []string
	Command       string // Raw command string (for Bash tool)
	Content       string // Content being written (for Write/Edit tools); may be overwritten by extractors
	RawJSON       string // Full re-marshaled JSON of all args (never overwritten by extractors)
	RawArgs       map[string]any
	Evasive       bool   // true if command uses shell tricks that prevent static analysis
	EvasiveReason string // human-readable reason for evasion detection
}

// addOperation adds op to info.Operations (deduplicated) and upgrades
// info.Operation if op has higher priority than the current primary.
// Use this for dynamic operations derived from arguments (output flags,
// interpreter code, redirects). For CommandInfo.ExtraOps use appendExtraOp.
func (info *ExtractedInfo) addOperation(op Operation) {
	if slices.Contains(info.Operations, op) {
		return
	}
	info.Operations = append(info.Operations, op)
	if operationPriority(op) > operationPriority(info.Operation) {
		info.Operation = op
	}
}

// appendExtraOp adds op to info.Operations without changing info.Operation.
// Used for CommandInfo.ExtraOps — the primary operation (info.Operation)
// reflects the command's typical classification declared in CommandInfo.Operation;
// ExtraOps are secondary capabilities that matter for rule matching but do not
// override the primary classification.
func (info *ExtractedInfo) appendExtraOp(op Operation) {
	if !slices.Contains(info.Operations, op) {
		info.Operations = append(info.Operations, op)
		// Intentionally does NOT update info.Operation
	}
}

// forceOperation sets info.Operation regardless of priority and adds op to
// info.Operations. Use when runtime argument analysis reveals a more specific
// primary classification than the command's general category — for example,
// when interpreter -c code reads a file (OpRead overrides OpExecute), or when
// a WebFetch URL is a file:// path (OpRead overrides OpNetwork).
func (info *ExtractedInfo) forceOperation(op Operation) {
	info.Operation = op
	if !slices.Contains(info.Operations, op) {
		info.Operations = append(info.Operations, op)
	}
}

// normalizeParsedCmdName normalizes a raw command name from the shell AST into
// its canonical form before it is stored in parsedCommand.Name.
//
// "[" is the POSIX alias for "test" (both are mandated by POSIX and present on
// Linux, macOS, and Windows POSIX environments like MSYS2/Cygwin/Git Bash).
// Storing "test" from the start means all downstream code (commandDB lookup,
// glob check, logging) sees a consistent name without each call site needing a
// special case for "[".
func normalizeParsedCmdName(name string) string {
	if name == "[" {
		return "test"
	}
	// .NET static calls: lowercase for case-insensitive DB lookup.
	// PS cmdlets (Verb-Noun) keep their original case; commandDB lookups
	// use strings.ToLower(cmdName) so no pre-normalization is needed.
	if strings.Contains(name, "::") {
		return strings.ToLower(name)
	}
	return name
}

// stripPathPrefix returns the base name of a command path, normalising
// backslashes to forward slashes first so the same logic handles both Unix
// paths (/usr/bin/cat → cat) and Windows paths (C:\Windows\cmd.exe → cmd.exe).
func stripPathPrefix(s string) string {
	return path.Base(pathutil.ToSlash(s))
}

// parsedCommand represents a single command extracted from a shell AST.
type parsedCommand struct {
	Name         string   `json:"name"`
	Args         []string `json:"args"`
	HasSubst     bool     `json:"has_subst"`      // true if any arg contains $() or backticks
	RedirPaths   []string `json:"redir_paths"`    // paths from output redirections (>, >>)
	RedirInPaths []string `json:"redir_in_paths"` // paths from input redirections (<)
}

// shellExecResult bundles the three values returned by runShellFile and
// runShellFileInterp so callers don't need to declare three separate variables.
type shellExecResult struct {
	cmds     []parsedCommand
	sym      map[string]string
	panicked bool
}

// normalizeFieldName produces a canonical form for argument field names.
// It lowercases and strips underscores/hyphens so that "target_file" (Cursor),
// "TargetFile" (Windsurf PascalCase), and "targetfile" all match the same entry.
// This is applied both to incoming JSON keys and to entries in the known-field lists.
func normalizeFieldName(name string) string {
	return strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(name))
}

// knownPathFields lists argument field names that typically contain file paths.
// All entries are in normalized form (lowercase, no underscores/hyphens).
// Covers Claude Code, OpenClaw, Cursor, and Windsurf Cascade.
var knownPathFields = []string{
	"path", "filepath", "filename", "file",
	"source", "destination", "target",
	"targetfile",            // Cursor target_file / Windsurf TargetFile
	"relativeworkspacepath", // Cursor relative_workspace_path
	"absolutepath",          // Windsurf AbsolutePath
	"projectpath",           // Windsurf ProjectPath
	"searchdirectory",       // Windsurf SearchDirectory
	"directorypath",         // Windsurf DirectoryPath
	"searchpath",            // Windsurf SearchPath
}

// knownContentFields lists argument field names that typically contain file content.
// All entries are in normalized form (lowercase, no underscores/hyphens).
// Covers Claude Code, OpenClaw, Cursor, and Windsurf Cascade.
var knownContentFields = []string{
	"content", "newstring",
	"codeedit",     // Cursor code_edit / Windsurf CodeEdit
	"instructions", // Cursor
	"instruction",  // Windsurf
	"codecontent",  // Windsurf CodeContent
	// NOTE: "text" and "data" intentionally excluded — too generic (search queries,
	// API responses). Combined with a path field, they falsely infer OpWrite.
}

// knownURLFields lists argument field names that typically contain URLs.
// All entries are in normalized form (lowercase, no underscores/hyphens).
var knownURLFields = []string{
	"url", "uri", "endpoint", "baseurl", "apiurl",
	"serverurl", "webhook", "callbackurl", "redirecturl",
}

// knownCommandFields lists argument field names that typically contain shell commands.
// All entries are in normalized form (lowercase, no underscores/hyphens).
var knownCommandFields = []string{
	"command",      // Claude Code Bash, OpenClaw exec
	"cmd",          // common abbreviation
	"commandline",  // Windsurf CommandLine
	"script",       // script execution tools
	"shellcommand", // explicit shell tools
	"shell",        // generic shell field
	// NOTE: "input" intentionally excluded — too generic (translations, search, chat).
	// Non-shell text that fails AST parsing triggers Evasive=true → hard block.
}

// fieldStrings recursively extracts all string values from a field value.
// Handles string, []any (from JSON arrays or case-collision merging), and
// map[string]any (nested JSON objects). Recursion ensures that strings
// buried inside nested structures are still extracted for rule matching —
// without this, {"path":{"value":"/etc/passwd"}} would silently bypass
// path-based rules.
// This is the single point of type normalization — all extraction
// functions use this instead of inline type assertions.
func fieldStrings(val any) []string {
	switch v := val.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []any:
		var result []string
		for _, item := range v {
			result = append(result, fieldStrings(item)...)
		}
		return result
	case map[string]any:
		var result []string
		for _, child := range v {
			result = append(result, fieldStrings(child)...)
		}
		return result
	}
	return nil
}

// FindPwsh returns the path to pwsh.exe or powershell.exe, preferring the
// newer pwsh (PowerShell 7+) over legacy powershell (Windows PowerShell 5.1).
// This is a package-level convenience wrapper around pwsh.FindPwsh.
func FindPwsh() (string, bool) {
	return pwsh.FindPwsh()
}

// Extractor extracts paths and operations from tool calls
type Extractor struct {
	commandDB  map[string]CommandInfo
	env        map[string]string // process environment for shell expansion
	worker     *shellWorker      // nil if subprocess isolation is disabled
	pwshWorker *pwsh.WorkerPool  // nil on non-Windows or if pwsh not found
}

// EnableSubprocessIsolation starts a worker subprocess for crash-isolated
// shell interpretation. If the interpreter panics in a goroutine spawned
// by the mvdan.cc/sh library, the subprocess crashes instead of the main
// process. Falls back to in-process interpretation if the worker dies.
func (e *Extractor) EnableSubprocessIsolation(exePath string) error {
	w, err := newShellWorker(exePath)
	if err != nil {
		return err
	}
	e.worker = w
	return nil
}

// EnablePSWorker starts a pool of pwsh worker subprocesses for accurate
// PowerShell command analysis. pwshPath must be the path to pwsh.exe or
// powershell.exe. Only call this on Windows (GOOS=windows covers both native
// and MSYS2/Cygwin) — the subprocesses are real, not no-ops. The call site
// in engine.go is gated behind runtime.GOOS == "windows". Falls back to
// the heuristic PS transform if this method is not called or returns an error.
func (e *Extractor) EnablePSWorker(pwshPath string) error {
	pool, err := pwsh.NewWorkerPool(pwshPath, 0) // 0 = auto-size
	if err != nil {
		return err
	}
	e.pwshWorker = pool
	return nil
}

// Close cleans up resources. Call when the Extractor is no longer needed.
func (e *Extractor) Close() {
	if e.worker != nil {
		e.worker.stop()
		e.worker = nil
	}
	if e.pwshWorker != nil {
		e.pwshWorker.Stop()
		e.pwshWorker = nil
	}
}

// CommandInfo describes how to extract info from a command
type CommandInfo struct {
	Operation    Operation   // primary (highest-priority) operation
	ExtraOps     []Operation // additional operations this command can perform
	PathArgIndex []int       // positional args that are paths
	PathFlags    []string    // flags followed by paths (-o, --output)
	SkipFlags    []string    // flags followed by non-path values (-n, --count)
}

// AllOperations returns all operations for this command (primary + extra).
func (c CommandInfo) AllOperations() []Operation {
	if len(c.ExtraOps) == 0 {
		return []Operation{c.Operation}
	}
	ops := make([]Operation, 0, 1+len(c.ExtraOps))
	ops = append(ops, c.Operation)
	ops = append(ops, c.ExtraOps...)
	return ops
}

// NewExtractor creates a new Extractor with the default command database
// and the current process environment for shell variable expansion.
func NewExtractor() *Extractor {
	env := make(map[string]string)
	for _, e := range os.Environ() {
		if key, value, ok := strings.Cut(e, "="); ok {
			env[key] = value
		}
	}
	return &Extractor{
		commandDB: defaultCommandDB(),
		env:       env,
	}
}

// NewExtractorWithEnv creates an Extractor with a custom environment.
// Useful for testing with deterministic variable values.
func NewExtractorWithEnv(env map[string]string) *Extractor {
	if env == nil {
		env = make(map[string]string)
	}
	return &Extractor{
		commandDB: defaultCommandDB(),
		env:       env,
	}
}

// defaultCommandDB returns the default command database
func defaultCommandDB() map[string]CommandInfo {
	db := map[string]CommandInfo{
		// ===========================================
		// READ OPERATIONS
		// ===========================================
		"cat":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
		"head": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}, SkipFlags: []string{"-n", "--lines", "-c", "--bytes"}},
		"tail": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}, SkipFlags: []string{"-n", "--lines", "-c", "--bytes"}},
		"less": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"more": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"grep": {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}, SkipFlags: []string{"-e", "--regexp", "-m", "--max-count", "-A", "-B", "-C", "--context"}},
		"vim":  {Operation: OpRead, ExtraOps: []Operation{OpWrite}, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"vi":   {Operation: OpRead, ExtraOps: []Operation{OpWrite}, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"nano": {Operation: OpRead, ExtraOps: []Operation{OpWrite}, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"view": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}}, // read-only vi variant

		// Directory listing
		"ls":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"exa": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"eza": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"lsd": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},

		// Binary inspection tools
		"strings": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"xxd":     {Operation: OpRead, PathArgIndex: []int{0}},
		"od":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"hexdump": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"hd":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2}}, // hexdump -C alias
		"base64":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"base32":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"file":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"stat":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"readelf": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"objdump": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"nm":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"ldd":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"size":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},

		// Encoding tools (GTFOBins: file-read)
		"uuencode": {Operation: OpRead, PathArgIndex: []int{0}},
		"uudecode": {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-o"}},
		"iconv":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o", "--output"}, SkipFlags: []string{"-f", "--from-code", "-t", "--to-code"}},

		// Hashing/checksum tools (must read file to compute hash)
		"md5sum":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"md5":       {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}}, // macOS
		"sha1sum":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"sha224sum": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"sha256sum": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"sha384sum": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"sha512sum": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"shasum":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}, SkipFlags: []string{"-a", "--algorithm"}},
		"cksum":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"sum":       {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"b2sum":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},

		// Text processing (read)
		"awk":   {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5}, PathFlags: []string{"-f", "--file"}},
		"gawk":  {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5}, PathFlags: []string{"-f", "--file"}},
		"mawk":  {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5}, PathFlags: []string{"-f"}},
		"nawk":  {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5}, PathFlags: []string{"-f"}},
		"sed":   {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5}, PathFlags: []string{"-f", "--file"}}, // -i becomes write (extractor_commands.go)
		"cut":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"sort":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"uniq":  {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"wc":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"diff":  {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"sdiff": {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"diff3": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"cmp":   {Operation: OpRead, PathArgIndex: []int{0, 1}, SkipFlags: []string{"-n", "--bytes"}},
		"shuf":  {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-o", "--output"}, SkipFlags: []string{"-i", "-n", "--input-range", "--head-count"}},
		"split": {Operation: OpRead, PathArgIndex: []int{0}, SkipFlags: []string{"-n", "--number", "-l", "--lines", "-b", "--bytes", "-a", "--suffix-length"}},
		"tsort": {Operation: OpRead, PathArgIndex: []int{0}},

		// Grep variants
		"egrep": {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}, SkipFlags: []string{"-e", "--regexp", "-m", "--max-count", "-A", "-B", "-C", "--context"}},
		"fgrep": {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}, SkipFlags: []string{"-e", "--regexp", "-m", "--max-count", "-A", "-B", "-C", "--context"}},
		"rg":    {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}, SkipFlags: []string{"-e", "--regexp", "-m", "--max-count", "-A", "-B", "-C", "--context", "-t", "--type", "-g", "--glob"}},

		// Editors (GTFOBins: file-read)
		"ed":    {Operation: OpRead, ExtraOps: []Operation{OpWrite}, PathArgIndex: []int{0}},
		"ex":    {Operation: OpRead, ExtraOps: []Operation{OpWrite}, PathArgIndex: []int{0, 1, 2, 3}},
		"emacs": {Operation: OpRead, ExtraOps: []Operation{OpWrite}, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"rview": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}}, // read-only vim variant
		"rvim":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}}, // restricted vim (no shell/write cmds)
		"pico":  {Operation: OpRead, ExtraOps: []Operation{OpWrite}, PathArgIndex: []int{0, 1, 2}},

		// Pagers / display tools
		"pg":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"ul":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"bat":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"batcat": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}}, // Debian package name

		// Additional text tools (read)
		"tac":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"rev":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"nl":       {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"paste":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"join":     {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"comm":     {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"column":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"pr":       {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"fold":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"fmt":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"expand":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"unexpand": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"look":     {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"csplit":   {Operation: OpRead, PathArgIndex: []int{0}},
		"pv":       {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}}, // pipe viewer

		// Structured data tools (read)
		"jq":      {Operation: OpRead, PathArgIndex: []int{1, 2, 3}},
		"yq":      {Operation: OpRead, PathArgIndex: []int{1, 2, 3}},
		"openssl": {Operation: OpRead, PathFlags: []string{"-in", "-out"}},
		"sqlite3": {Operation: OpRead, PathArgIndex: []int{0}},
		"csvtool": {Operation: OpRead, PathArgIndex: []int{1, 2, 3}},
		"mysql":   {Operation: OpRead, PathArgIndex: []int{0}, SkipFlags: []string{"-u", "--user", "-p", "--password", "-h", "--host", "-P", "--port", "-D", "--database"}},
		"psql":    {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-f", "--file"}, SkipFlags: []string{"-U", "--username", "-h", "--host", "-p", "--port", "-d", "--dbname"}},

		// Document formatting / typesetting (GTFOBins: file-read)
		"nroff":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"groff":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"troff":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"pandoc":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o", "--output"}},
		"enscript": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o", "--output"}},
		"a2ps":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o", "--output"}},

		// Archive tools (read contents)
		"tar":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-f", "--file"}},
		"zip":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"unzip":   {Operation: OpWrite, PathArgIndex: []int{0}},
		"gzip":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"gunzip":  {Operation: OpRead, ExtraOps: []Operation{OpWrite}, PathArgIndex: []int{0, 1, 2}}, // reads compressed, writes decompressed
		"zcat":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"bzip2":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"bunzip2": {Operation: OpRead, ExtraOps: []Operation{OpWrite}, PathArgIndex: []int{0, 1, 2}},
		"bzcat":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"xz":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"xzcat":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"lzma":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"unlzma":  {Operation: OpRead, ExtraOps: []Operation{OpWrite}, PathArgIndex: []int{0, 1, 2}},
		"lzcat":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"zstd":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"unzstd":  {Operation: OpRead, ExtraOps: []Operation{OpWrite}, PathArgIndex: []int{0, 1, 2}},
		"zstdcat": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"lz4":     {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"lz4cat":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"unlz4":   {Operation: OpRead, ExtraOps: []Operation{OpWrite}, PathArgIndex: []int{0, 1}},
		"cpio":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-F", "--file", "-I", "-E"}},
		"ar":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"7z":      {Operation: OpRead, PathArgIndex: []int{1, 2, 3}},
		"7za":     {Operation: OpRead, PathArgIndex: []int{1, 2, 3}},

		// ===========================================
		// WRITE OPERATIONS
		// ===========================================
		"tee":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"touch":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"install":  {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}, SkipFlags: []string{"-m", "--mode", "-o", "--owner", "-g", "--group"}},
		"mkdir":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"sponge":   {Operation: OpWrite, PathArgIndex: []int{0}},
		"truncate": {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-r", "--reference"}, SkipFlags: []string{"-s", "--size"}},
		"patch":    {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-i", "--input", "-o", "--output"}},
		"chmod":    {Operation: OpWrite, PathArgIndex: []int{1, 2, 3, 4, 5}}, // arg0 = mode
		"chown":    {Operation: OpWrite, PathArgIndex: []int{1, 2, 3, 4, 5}}, // arg0 = owner[:group]
		"chgrp":    {Operation: OpWrite, PathArgIndex: []int{1, 2, 3, 4, 5}}, // arg0 = group

		// Compiler / build tools
		"gcc":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o"}},
		"g++":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o"}},
		"cc":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o"}},
		"c++":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o"}},
		"clang":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o"}},
		"clang++": {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o"}},
		"rustc":   {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-o"}},
		"javac":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-d"}},
		"as":      {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-o"}},
		"ld":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o"}},
		"strip":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"ranlib":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"cmake":   {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-S", "-B", "--build"}},
		"ninja":   {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-C"}},
		"meson":   {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"go":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}, PathFlags: []string{"-o"}},
		"cargo":   {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},

		// Package managers
		"pip":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}, PathFlags: []string{"-t", "--target", "-r", "--requirement"}},
		"pip3":     {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}, PathFlags: []string{"-t", "--target", "-r", "--requirement"}},
		"npm":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"yarn":     {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"pnpm":     {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"gem":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"composer": {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"brew":     {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"apt":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"apt-get":  {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"dpkg":     {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-i", "--install"}},
		"rpm":      {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-i", "--install", "-U", "--upgrade"}},
		"snap":     {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"flatpak":  {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"pacman":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-U"}},
		"yum":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"dnf":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"apk":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"zypper":   {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"port":     {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"dotnet":   {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}, PathFlags: []string{"-o", "--output"}},
		"mvn":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"gradle":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},

		// Encryption / signing
		"gpg":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o", "--output"}},
		"gpg2":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o", "--output"}},
		"age":     {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-o", "--output"}},
		"signify": {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-s", "-p", "-m"}},

		// Image / media conversion
		"convert":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"magick":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"ffmpeg":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-i"}},
		"ffprobe":     {Operation: OpRead, PathArgIndex: []int{0}},
		"sox":         {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"lame":        {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"flac":        {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"optipng":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"pngcrush":    {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"jpegoptim":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"gifsicle":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o", "--output"}},
		"wkhtmltopdf": {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"weasyprint":  {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"exiftool":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},

		// GTFOBins file-write binaries
		"gdb":    {Operation: OpExecute, ExtraOps: []Operation{OpRead}, PathArgIndex: []int{0, 1}, PathFlags: []string{"-x", "--command", "--core"}},
		"lldb":   {Operation: OpExecute, ExtraOps: []Operation{OpRead}, PathArgIndex: []int{0, 1}, PathFlags: []string{"-o", "-s", "-S", "--source", "--one-line"}},
		"screen": {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-L", "-Logfile"}},
		"tmux":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"script": {Operation: OpWrite, PathArgIndex: []int{0}},

		// Filesystem metadata modification
		"chattr":  {Operation: OpWrite, PathArgIndex: []int{1, 2, 3, 4, 5}},
		"setfacl": {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}, PathFlags: []string{"-M", "--modify-file", "-X", "--remove-file"}, SkipFlags: []string{"-m", "--modify", "-x", "--remove"}},
		"xattr":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"chflags": {Operation: OpWrite, PathArgIndex: []int{1, 2, 3, 4, 5}},

		// File creation / allocation
		"fallocate": {Operation: OpWrite, PathArgIndex: []int{0, 1}, SkipFlags: []string{"-l", "--length", "-o", "--offset"}},
		"mknod":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfifo":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"mktemp":    {Operation: OpWrite, PathFlags: []string{"-p", "--tmpdir"}},

		// Disk / filesystem / partition tools
		"mkfs":       {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.ext2":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.ext3":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.ext4":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.xfs":   {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.btrfs": {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.vfat":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.ntfs":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"mke2fs":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"newfs":      {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkswap":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"wipefs":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"fdisk":      {Operation: OpWrite, PathArgIndex: []int{0}},
		"gdisk":      {Operation: OpWrite, PathArgIndex: []int{0}},
		"sgdisk":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"parted":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"sfdisk":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"losetup":    {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"mount":      {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"umount":     {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"cryptsetup": {Operation: OpWrite, PathArgIndex: []int{1, 2}},
		"e2fsck":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"fsck":       {Operation: OpWrite, PathArgIndex: []int{0}},
		"tune2fs":    {Operation: OpWrite, PathArgIndex: []int{0}},
		"resize2fs":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"xfs_repair": {Operation: OpWrite, PathArgIndex: []int{0}},
		"btrfs":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},

		// Archive creation tools
		"mksquashfs":  {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"mkisofs":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o"}},
		"genisoimage": {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o"}},
		"xorriso":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-outdev"}},
		"pax":         {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-f"}},

		// macOS-specific write tools
		"plutil":            {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"defaults":          {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"PlistBuddy":        {Operation: OpWrite, PathArgIndex: []int{0}},
		"hdiutil":           {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"diskutil":          {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"codesign":          {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"launchctl":         {Operation: OpWrite, PathArgIndex: []int{1, 2}},
		"scutil":            {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"installer":         {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-pkg", "-target"}},
		"lipo":              {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-output"}},
		"install_name_tool": {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"dscl":              {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"sips":              {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o", "--out"}},
		"textutil":          {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-output"}},

		// systemd / service management
		"systemctl":   {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"hostnamectl": {Operation: OpWrite, PathArgIndex: []int{1, 2}},
		"journalctl":  {Operation: OpRead, PathArgIndex: []int{}},

		// User/group management
		"useradd":  {Operation: OpWrite, PathArgIndex: []int{0}, SkipFlags: []string{"-u", "--uid", "-g", "--gid", "-d", "--home", "-s", "--shell", "-c", "--comment"}},
		"usermod":  {Operation: OpWrite, PathArgIndex: []int{0}, SkipFlags: []string{"-u", "--uid", "-g", "--gid", "-d", "--home", "-s", "--shell", "-l", "--login"}},
		"groupadd": {Operation: OpWrite, PathArgIndex: []int{0}},
		"groupmod": {Operation: OpWrite, PathArgIndex: []int{0}},
		"passwd":   {Operation: OpWrite, PathArgIndex: []int{0}},
		"hardlink": {Operation: OpWrite, PathArgIndex: []int{0, 1}},

		// ===========================================
		// DELETE OPERATIONS
		// ===========================================
		"rm":        {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
		"unlink":    {Operation: OpDelete, PathArgIndex: []int{0}},
		"shred":     {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"rmdir":     {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"srm":       {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}}, // secure-delete
		"wipe":      {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"trash":     {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"trash-put": {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},

		// GNOME/desktop trash
		"gio":        {Operation: OpDelete, PathArgIndex: []int{1, 2, 3}},
		"gvfs-trash": {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3}},

		// User/group deletion
		"userdel":  {Operation: OpDelete, PathArgIndex: []int{0}},
		"groupdel": {Operation: OpDelete, PathArgIndex: []int{0}},

		// Windows delete
		"del":   {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"erase": {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"rd":    {Operation: OpDelete, PathArgIndex: []int{0, 1, 2}},

		// ===========================================
		// COPY OPERATIONS
		// ===========================================
		"cp":       {Operation: OpCopy, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"scp":      {Operation: OpCopy, PathArgIndex: []int{0, 1}},
		"rsync":    {Operation: OpCopy, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"dd":       {Operation: OpCopy, PathFlags: []string{"if=", "of="}},
		"ditto":    {Operation: OpCopy, PathArgIndex: []int{0, 1}},       // macOS advanced copy
		"robocopy": {Operation: OpCopy, PathArgIndex: []int{0, 1, 2, 3}}, // Windows
		"xcopy":    {Operation: OpCopy, PathArgIndex: []int{0, 1}},       // Windows
		"copy":     {Operation: OpCopy, PathArgIndex: []int{0, 1}},       // Windows

		// ===========================================
		// MOVE OPERATIONS
		// ===========================================
		"mv":     {Operation: OpMove, PathArgIndex: []int{0, 1}},
		"move":   {Operation: OpMove, PathArgIndex: []int{0, 1}}, // Windows
		"ren":    {Operation: OpMove, PathArgIndex: []int{0, 1}}, // Windows rename
		"rename": {Operation: OpMove, PathArgIndex: []int{0, 1}},

		// ===========================================
		// NETWORK OPERATIONS
		// ===========================================
		"curl":           {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-o", "--output"}},
		"wget":           {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-O", "--output-document", "--post-file", "--body-file"}},
		"nc":             {Operation: OpNetwork, ExtraOps: []Operation{OpExecute}, PathArgIndex: []int{0}}, // supports -e for remote code execution
		"nc.traditional": {Operation: OpNetwork, ExtraOps: []Operation{OpExecute}, PathArgIndex: []int{0}},
		"nc.openbsd":     {Operation: OpNetwork, ExtraOps: []Operation{OpExecute}, PathArgIndex: []int{0}},
		"netcat":         {Operation: OpNetwork, ExtraOps: []Operation{OpExecute}, PathArgIndex: []int{0}},
		"ssh":            {Operation: OpNetwork, ExtraOps: []Operation{OpExecute}, PathArgIndex: []int{0}},       // executes remote commands
		"sftp":           {Operation: OpNetwork, ExtraOps: []Operation{OpRead, OpWrite}, PathArgIndex: []int{0}}, // reads/writes remote files
		"ftp":            {Operation: OpNetwork, ExtraOps: []Operation{OpRead, OpWrite}, PathArgIndex: []int{0}}, // get/put
		"telnet":         {Operation: OpNetwork, ExtraOps: []Operation{OpExecute}, PathArgIndex: []int{0}},       // interactive shell access
		"nmap":           {Operation: OpNetwork, PathArgIndex: []int{0, 1, 2, 3}},
		"ping":           {Operation: OpNetwork, PathArgIndex: []int{0}},
		"dig":            {Operation: OpNetwork, PathArgIndex: []int{0}},
		"nslookup":       {Operation: OpNetwork, PathArgIndex: []int{0}},
		"socat":          {Operation: OpRead, PathArgIndex: []int{0, 1}},                                   // upgraded to execute/network based on address types in args
		"ncat":           {Operation: OpNetwork, ExtraOps: []Operation{OpExecute}, PathArgIndex: []int{0}}, // --exec/--sh-exec for remote code execution
		"aria2c":         {Operation: OpNetwork, PathArgIndex: []int{0}},
		"http":           {Operation: OpNetwork, PathArgIndex: []int{0, 1, 2}},
		"whois":          {Operation: OpNetwork, PathArgIndex: []int{0}},

		// Credential/cloud tools (can expose secrets via network)
		"git":     {Operation: OpNetwork, PathArgIndex: []int{1, 2, 3}},
		"docker":  {Operation: OpExecute, PathArgIndex: []int{1, 2, 3}},
		"kubectl": {Operation: OpNetwork, PathArgIndex: []int{1, 2, 3}},
		"aws":     {Operation: OpNetwork, PathArgIndex: []int{2, 3, 4}},
		"gcloud":  {Operation: OpNetwork, PathArgIndex: []int{2, 3, 4}},
		"az":      {Operation: OpNetwork, PathArgIndex: []int{2, 3, 4}},

		// ===========================================
		// EXECUTE OPERATIONS
		// ===========================================
		"bash":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"sh":      {Operation: OpExecute, PathArgIndex: []int{0}},
		"zsh":     {Operation: OpExecute, PathArgIndex: []int{0}},
		"dash":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"ksh":     {Operation: OpExecute, PathArgIndex: []int{0}},
		"csh":     {Operation: OpExecute, PathArgIndex: []int{0}},
		"tcsh":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"fish":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"python":  {Operation: OpExecute, PathArgIndex: []int{0}},
		"python2": {Operation: OpExecute, PathArgIndex: []int{0}},
		"python3": {Operation: OpExecute, PathArgIndex: []int{0}},
		"node":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"ruby":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"perl":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"php":     {Operation: OpExecute, PathArgIndex: []int{0}},
		"lua":     {Operation: OpExecute, PathArgIndex: []int{0}},
		"luajit":  {Operation: OpExecute, PathArgIndex: []int{0}},
		"tclsh":   {Operation: OpExecute, PathArgIndex: []int{0}},
		"wish":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"Rscript": {Operation: OpExecute, PathArgIndex: []int{0}},

		// Indirect execution
		"xargs":  {Operation: OpExecute, PathFlags: []string{"-a", "--arg-file"}, PathArgIndex: []int{1, 2, 3}}, // arg0 is command name; args 1+ are paths passed to it
		"find":   {Operation: OpRead, ExtraOps: []Operation{OpExecute}, PathArgIndex: []int{0}},                 // searches dirs (read), may -exec commands
		"eval":   {Operation: OpExecute, PathArgIndex: []int{0}},
		"source": {Operation: OpExecute, PathArgIndex: []int{0}},
		".":      {Operation: OpExecute, PathArgIndex: []int{0}}, // source alias
		"make":   {Operation: OpExecute, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-f", "--file", "-C", "--directory"}},

		// Additional runtimes
		"npx":    {Operation: OpExecute, PathArgIndex: []int{0, 1, 2}},
		"bun":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"deno":   {Operation: OpExecute, PathArgIndex: []int{0, 1}},
		"swift":  {Operation: OpExecute, PathArgIndex: []int{0}},
		"java":   {Operation: OpExecute, PathArgIndex: []int{0, 1, 2}},
		"julia":  {Operation: OpExecute, PathArgIndex: []int{0}},
		"elixir": {Operation: OpExecute, PathArgIndex: []int{0}},
		"expect": {Operation: OpExecute, PathArgIndex: []int{0}},
		"erl":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"groovy": {Operation: OpExecute, PathArgIndex: []int{0}},
		"scala":  {Operation: OpExecute, PathArgIndex: []int{0}},
		"kotlin": {Operation: OpExecute, PathArgIndex: []int{0}},

		// Windows shells and LOLBAS
		// -Command/-EncodedCommand are handled by the dedicated PowerShell handler
		// in extractFromParsedCommandsDepth (not as PathFlags). Only -File remains
		// as a PathFlag since it genuinely takes a file path.
		"powershell":     {Operation: OpExecute, PathFlags: []string{"-File"}, SkipFlags: []string{"-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "-WindowStyle", "-OutputFormat", "-InputFormat"}},
		"powershell.exe": {Operation: OpExecute, PathFlags: []string{"-File"}, SkipFlags: []string{"-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "-WindowStyle", "-OutputFormat", "-InputFormat"}},
		"pwsh":           {Operation: OpExecute, PathFlags: []string{"-File"}, SkipFlags: []string{"-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "-WindowStyle", "-OutputFormat", "-InputFormat"}},
		"pwsh.exe":       {Operation: OpExecute, PathFlags: []string{"-File"}, SkipFlags: []string{"-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "-WindowStyle", "-OutputFormat", "-InputFormat"}},
		"cmd.exe":        {Operation: OpExecute, PathArgIndex: []int{0}},
		"cmd":            {Operation: OpExecute, PathArgIndex: []int{0}},
		"mshta":          {Operation: OpExecute, PathArgIndex: []int{0}},
		"cscript":        {Operation: OpExecute, PathArgIndex: []int{0}},
		"wscript":        {Operation: OpExecute, PathArgIndex: []int{0}},
		"msiexec":        {Operation: OpExecute, PathArgIndex: []int{0, 1}, PathFlags: []string{"/i", "/p", "/a"}},
		"wmic":           {Operation: OpExecute, PathArgIndex: []int{0, 1, 2, 3}},
		"certutil":       {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}}, // LOLBAS: download+write
		"bitsadmin":      {Operation: OpNetwork, PathArgIndex: []int{0, 1, 2, 3}},
		"osascript":      {Operation: OpExecute, PathArgIndex: []int{0}},                                                                                                                                             // macOS AppleScript
		"nu":             {Operation: OpExecute, PathArgIndex: []int{0}},                                                                                                                                             // Nushell
		"nushell":        {Operation: OpExecute, PathArgIndex: []int{0}},                                                                                                                                             // Nushell (full name)
		"elvish":         {Operation: OpExecute, PathArgIndex: []int{0}},                                                                                                                                             // Elvish shell
		"oil":            {Operation: OpExecute, PathArgIndex: []int{0}},                                                                                                                                             // Oil shell
		"osh":            {Operation: OpExecute, PathArgIndex: []int{0}},                                                                                                                                             // Oil shell (POSIX mode)
		"ysh":            {Operation: OpExecute, PathArgIndex: []int{0}},                                                                                                                                             // Oil shell (new syntax)
		"rc":             {Operation: OpExecute, PathArgIndex: []int{0}},                                                                                                                                             // Plan 9 shell
		"es":             {Operation: OpExecute, PathArgIndex: []int{0}},                                                                                                                                             // Extensible shell
		"pwsh-preview":   {Operation: OpExecute, PathFlags: []string{"-File"}, SkipFlags: []string{"-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "-WindowStyle", "-OutputFormat", "-InputFormat"}}, // PowerShell preview

		// Windows file operations
		"type":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2}}, // Windows cat equivalent
		"attrib":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"icacls":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"cacls":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"takeown":  {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"/F", "/D"}},
		"mklink":   {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"cipher":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"compact":  {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"fsutil":   {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"diskpart": {Operation: OpWrite, PathArgIndex: []int{}},
		"format":   {Operation: OpWrite, PathArgIndex: []int{0}},
		"regedit":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"reg":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"sc":       {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"schtasks": {Operation: OpExecute, PathArgIndex: []int{0, 1, 2}},
		"forfiles": {Operation: OpExecute, PathArgIndex: []int{0, 1}, PathFlags: []string{"/P", "/M", "/C"}},
		"call":     {Operation: OpExecute, PathArgIndex: []int{0}}, // cmd.exe CALL built-in: executes a .bat/.cmd script

		// Scheduled task commands
		"crontab": {Operation: OpExecute, PathArgIndex: []int{}},
		"at":      {Operation: OpExecute, PathArgIndex: []int{}},

		// ===========================================
		// SYMLINK OPERATIONS (important for bypass detection)
		// ===========================================
		"ln":       {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"readlink": {Operation: OpRead, PathArgIndex: []int{0}},

		// ===========================================
		// POWERSHELL CMDLETS
		// ===========================================
		// PowerShell cmdlet names (e.g. "Get-Content") are valid POSIX command
		// names (hyphens allowed), so the Bash parser captures them as-is.
		// PathFlags use PowerShell named parameters (-Path, -LiteralPath, etc.).
		// Covers both full cmdlet names and common aliases not already in DB.

		// Read operations
		"Get-Content":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"gc":               {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Get-ChildItem":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-Path", "-LiteralPath", "-Filter"}},
		"gci":              {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-Path", "-LiteralPath", "-Filter"}},
		"dir":              {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"Select-String":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-Path", "-LiteralPath"}, SkipFlags: []string{"-Pattern"}},
		"sls":              {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Get-ItemProperty": {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Test-Path":        {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Import-Csv":       {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Get-Acl":          {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-Path"}},
		"Get-FileHash":     {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Import-Clixml":    {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"ConvertFrom-Json": {Operation: OpRead, PathArgIndex: []int{0}},

		// Write operations
		"Set-Content":      {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-LiteralPath", "-Value"}},
		"Add-Content":      {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-LiteralPath", "-Value"}},
		"ac":               {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Out-File":         {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-FilePath", "-LiteralPath"}},
		"New-Item":         {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-Name"}, SkipFlags: []string{"-ItemType"}},
		"ni":               {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-Name"}},
		"Set-ItemProperty": {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Clear-Content":    {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"clc":              {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Export-Csv":       {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Export-Clixml":    {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Set-Acl":          {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path"}},
		"Compress-Archive": {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-DestinationPath", "-LiteralPath"}},
		"Expand-Archive":   {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-DestinationPath", "-LiteralPath"}},

		// Delete operations
		"Remove-Item":         {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"ri":                  {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Clear-Item":          {Operation: OpDelete, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Remove-ItemProperty": {Operation: OpDelete, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},

		// Copy operations
		"Copy-Item": {Operation: OpCopy, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-Destination", "-LiteralPath"}},
		"ci":        {Operation: OpCopy, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-Destination", "-LiteralPath"}},

		// Move operations
		"Move-Item":   {Operation: OpMove, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-Destination", "-LiteralPath"}},
		"mi":          {Operation: OpMove, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-Destination", "-LiteralPath"}},
		"Rename-Item": {Operation: OpMove, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-NewName", "-LiteralPath"}},
		"rni":         {Operation: OpMove, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-NewName"}},

		// Network operations
		"Invoke-WebRequest":  {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-Uri", "-OutFile"}},
		"iwr":                {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-Uri", "-OutFile"}},
		"Invoke-RestMethod":  {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-Uri", "-OutFile"}},
		"irm":                {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-Uri", "-OutFile"}},
		"Send-MailMessage":   {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-Attachments"}, SkipFlags: []string{"-To", "-From", "-SmtpServer"}},
		"Test-NetConnection": {Operation: OpNetwork, PathArgIndex: []int{0}, SkipFlags: []string{"-ComputerName", "-Port"}},
		"Resolve-DnsName":    {Operation: OpNetwork, PathArgIndex: []int{0}},

		// Execute operations
		"Invoke-Expression":      {Operation: OpExecute, PathArgIndex: []int{0}}, // -Command handled by recursive PS parser above
		"iex":                    {Operation: OpExecute, PathArgIndex: []int{0}},
		"Start-Process":          {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-FilePath", "-ArgumentList"}},
		"Invoke-Item":            {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"ii":                     {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"saps":                   {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-FilePath"}},
		"Invoke-Command":         {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-ScriptBlock", "-FilePath", "-ComputerName"}},
		"icm":                    {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-ScriptBlock", "-FilePath"}},
		"Import-Module":          {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-Name"}},
		"ipmo":                   {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-Name"}},
		"Add-Type":               {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-AssemblyName"}},
		"Register-ScheduledTask": {Operation: OpExecute, PathArgIndex: []int{0}},
		"Start-Job":              {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-ScriptBlock", "-FilePath"}},

		// .NET static API calls — keys are lowercased (normalizeParsedCmdName
		// lowercases any name containing "::").
		// System.IO.File
		"system.io.file::readalltext":    {Operation: OpRead, PathArgIndex: []int{0}},
		"system.io.file::readallbytes":   {Operation: OpRead, PathArgIndex: []int{0}},
		"system.io.file::readalllines":   {Operation: OpRead, PathArgIndex: []int{0}},
		"system.io.file::openread":       {Operation: OpRead, PathArgIndex: []int{0}},
		"system.io.file::open":           {Operation: OpRead, PathArgIndex: []int{0}},
		"system.io.file::exists":         {Operation: OpRead, PathArgIndex: []int{0}},
		"system.io.file::writealltext":   {Operation: OpWrite, PathArgIndex: []int{0}},
		"system.io.file::writeallbytes":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"system.io.file::writealllines":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"system.io.file::appendalltext":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"system.io.file::appendalllines": {Operation: OpWrite, PathArgIndex: []int{0}},
		"system.io.file::openwrite":      {Operation: OpWrite, PathArgIndex: []int{0}},
		"system.io.file::create":         {Operation: OpWrite, PathArgIndex: []int{0}},
		"system.io.file::copy":           {Operation: OpCopy, PathArgIndex: []int{0, 1}},
		"system.io.file::move":           {Operation: OpMove, PathArgIndex: []int{0, 1}},
		"system.io.file::delete":         {Operation: OpDelete, PathArgIndex: []int{0}},
		// System.IO.Directory
		"system.io.directory::getfiles":         {Operation: OpRead, PathArgIndex: []int{0}},
		"system.io.directory::getdirectories":   {Operation: OpRead, PathArgIndex: []int{0}},
		"system.io.directory::getentryfssinfos": {Operation: OpRead, PathArgIndex: []int{0}},
		"system.io.directory::exists":           {Operation: OpRead, PathArgIndex: []int{0}},
		"system.io.directory::createdirectory":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"system.io.directory::move":             {Operation: OpMove, PathArgIndex: []int{0, 1}},
		"system.io.directory::delete":           {Operation: OpDelete, PathArgIndex: []int{0}},
		// System.Net — static helpers
		"system.net.dns::gethostaddresses": {Operation: OpNetwork, PathArgIndex: []int{0}},
		"system.net.dns::gethostentry":     {Operation: OpNetwork, PathArgIndex: []int{0}},
		"system.net.dns::resolve":          {Operation: OpNetwork, PathArgIndex: []int{0}},
		// System.Diagnostics.Process
		"system.diagnostics.process::start": {Operation: OpExecute, PathArgIndex: []int{0}},
		// System.Reflection.Assembly — dynamic code loading (high-severity)
		"system.reflection.assembly::loadfile": {Operation: OpExecute, PathArgIndex: []int{0}},
		"system.reflection.assembly::loadfrom": {Operation: OpExecute, PathArgIndex: []int{0}},
		"system.reflection.assembly::load":     {Operation: OpExecute, PathArgIndex: []int{0}},
		// Instance methods via New-Object (keys lowercased, :: separator)
		"system.net.webclient::downloadfile":   {Operation: OpWrite, PathArgIndex: []int{1}},
		"system.net.webclient::downloadstring": {Operation: OpNetwork, PathArgIndex: []int{0}},
		"system.net.webclient::uploadfile":     {Operation: OpRead, PathArgIndex: []int{1}},
		"system.net.webclient::uploadstring":   {Operation: OpNetwork, PathArgIndex: []int{0}},
		"system.net.webclient::openread":       {Operation: OpNetwork, PathArgIndex: []int{0}},
		// System.Net.WebClient — additional methods
		"system.net.webclient::uploaddata":   {Operation: OpNetwork, PathArgIndex: []int{0}},
		"system.net.webclient::downloaddata": {Operation: OpNetwork, PathArgIndex: []int{0}},
		// System.IO stream types
		"system.io.streamreader": {Operation: OpRead, PathArgIndex: []int{0}},
		"system.io.streamwriter": {Operation: OpWrite, PathArgIndex: []int{0}},
		"system.io.filestream":   {Operation: OpRead, PathArgIndex: []int{0}},
		// Microsoft.Win32.Registry
		"microsoft.win32.registrykey::opensubkey": {Operation: OpRead, PathArgIndex: []int{0}},
		"microsoft.win32.registrykey::setvalue":   {Operation: OpWrite, PathArgIndex: []int{0}},
		"microsoft.win32.registrykey::getvalue":   {Operation: OpRead, PathArgIndex: []int{0}},
		"microsoft.win32.registry::getvalue":      {Operation: OpRead, PathArgIndex: []int{0}},
		"microsoft.win32.registry::setvalue":      {Operation: OpWrite, PathArgIndex: []int{0}},
		// System.Net.Sockets
		"system.net.sockets.tcpclient::connect":      {Operation: OpNetwork, PathArgIndex: []int{0}},
		"system.net.sockets.tcpclient::connectasync": {Operation: OpNetwork, PathArgIndex: []int{0}},
		"system.net.sockets.udpclient::send":         {Operation: OpNetwork, PathArgIndex: []int{0}},
		"system.net.sockets.udpclient::sendasync":    {Operation: OpNetwork, PathArgIndex: []int{0}},
		"system.net.http.httpclient::getasync":       {Operation: OpNetwork, PathArgIndex: []int{0}},
		"system.net.http.httpclient::postasync":      {Operation: OpNetwork, PathArgIndex: []int{0}},
	}
	// Lowercase all PS cmdlet keys (Verb-Noun → verb-noun) for case-insensitive lookup.
	// Bash commands are already lowercase; .NET API keys are already lowercase.
	lc := make(map[string]CommandInfo, len(db))
	for k, v := range db {
		if strings.Contains(k, "-") {
			lc[strings.ToLower(k)] = v
		} else {
			lc[k] = v
		}
	}
	return lc
}

// Extract extracts info from a tool call
func (e *Extractor) Extract(toolName string, args json.RawMessage) ExtractedInfo {
	info := ExtractedInfo{
		RawArgs: make(map[string]any),
	}

	// Parse the raw args
	if err := json.Unmarshal(args, &info.RawArgs); err != nil {
		info.Content = string(args)
		return info
	}

	// SECURITY: Re-marshal decoded args for content matching.
	// json.Unmarshal decodes \uXXXX escapes → actual chars, then json.Marshal
	// writes them back as plain text. This prevents bypassing content-only rules
	// by encoding "localhost" as "\u006c\u006f\u0063\u0061\u006c\u0068\u006f\u0073\u0074".
	if normalized, err := json.Marshal(info.RawArgs); err == nil {
		info.Content = string(normalized)
		info.RawJSON = string(normalized)
	} else {
		info.Content = string(args)
		info.RawJSON = string(args)
	}

	// SECURITY: Normalize field names to canonical form (lowercase, no underscores/hyphens).
	// JSON keys are case-sensitive, so {"Command": "rm -rf /"} would bypass
	// detection if we only check lowercase field names. Additionally, different agents
	// use different naming conventions (snake_case: Cursor, PascalCase: Windsurf).
	// Normalizing once here makes "target_file", "TargetFile", "targetFile" all equivalent.
	// On collision (e.g., "command" and "Command" both present), merge values
	// into []any so ALL values are analyzed — Go map iteration is nondeterministic,
	// so a simple overwrite would randomly lose one value.
	lowered := make(map[string]any, len(info.RawArgs))
	for k, v := range info.RawArgs {
		lk := normalizeFieldName(k)
		if existing, ok := lowered[lk]; ok {
			switch arr := existing.(type) {
			case []any:
				lowered[lk] = append(arr, v)
			default:
				lowered[lk] = []any{arr, v}
			}
		} else {
			lowered[lk] = v
		}
	}
	info.RawArgs = lowered

	// Normalize tool name for comparison
	toolLower := strings.ToLower(toolName)

	// Layer 1: name-based extraction (fast path for known tools).
	// Tool names from: Claude Code, Codex CLI, OpenCode, OpenClaw, Cline, Cursor, Windsurf Cascade.
	switch toolLower {
	case "bash", "exec",
		"shell",            // Codex CLI
		"run_terminal_cmd", // Cursor
		"run_command",      // Windsurf
		"execute_command":  // Cline
		e.extractBashCommand(&info)
	case "read", "read_file",
		"view_line_range",            // Windsurf
		"view_file_outline",          // Windsurf
		"view_code_item",             // Windsurf
		"search_in_file",             // Windsurf
		"search_files",               // Cline
		"list_files",                 // Cline
		"list_code_definition_names", // Cline
		"codebase_search",            // Cursor
		"grep_search",                // Cursor
		"file_search",                // Cursor
		"list_dir":                   // Cursor / Codex
		e.extractReadTool(&info)
	case "write", "write_file",
		"write_to_file", // Cline / Windsurf
		"apply_patch",   // OpenClaw / Cursor
		"applypatch",    // Cursor (ApplyPatch → applypatch after lowering)
		"patch":         // OpenCode
		e.extractWriteTool(&info)
	case "edit", "edit_file", // Cursor / Windsurf
		"multiedit",       // Claude Code
		"replace_in_file": // Cline
		e.extractEditTool(&info)
	case "delete_file": // Cursor
		e.extractDeleteTool(&info)
	case "webfetch", "web_fetch", "websearch", "web_search", "browser",
		"read_url_content",                // Windsurf
		"view_web_document_content_chunk", // Windsurf
		"browser_preview",                 // Windsurf
		"search_web",                      // Windsurf
		"browser_action":                  // Cline
		e.extractWebFetchTool(&info)
	default:
		// Unknown tool — try shell AST parsing on any command-like field first,
		// then fall back to shape-based detection for paths/urls/content.
		e.extractUnknownTool(&info)
	}

	// Layer 2: shape-based augmentation (always runs, never downgrades)
	// Catches renamed tools, hidden fields, and MCP tools with standard arg shapes.
	e.augmentFromArgShape(&info)

	// Expand Windows cmd.exe %VAR% references in extracted paths using the
	// extractor's env map. normalizeWinPaths already converted backslashes to
	// forward slashes (%USERPROFILE%\.env → %USERPROFILE%/.env), so we only
	// need to substitute the %VAR% tokens with their env values.
	e.expandPercentVars(&info)

	// Ensure Operations is always populated from Operation (for tool extractors
	// that set info.Operation directly rather than calling addOperation).
	if info.Operation != OpNone && len(info.Operations) == 0 {
		info.Operations = []Operation{info.Operation}
	}

	return info
}
