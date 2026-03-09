package rules

import (
	"net/url"
	"path"
	"strings"

	"github.com/BakeLens/crust/internal/pathutil"
)

// extractReadTool extracts info from Read/read_file tool
func (e *Extractor) extractReadTool(info *ExtractedInfo) {
	info.addOperation(OpRead)
	e.extractPathFields(info)
}

// extractWriteTool extracts info from Write/write_file tool
func (e *Extractor) extractWriteTool(info *ExtractedInfo) {
	info.addOperation(OpWrite)
	e.extractPathFields(info)
	e.extractContentField(info)
}

// extractEditTool extracts info from Edit tool
func (e *Extractor) extractEditTool(info *ExtractedInfo) {
	info.addOperation(OpWrite)
	e.extractPathFields(info)
	e.extractContentField(info)
}

// extractDeleteTool extracts info from delete_file tool (Cursor)
func (e *Extractor) extractDeleteTool(info *ExtractedInfo) {
	info.addOperation(OpDelete)
	e.extractPathFields(info)
}

// extractUnknownTool handles the default case in Layer 1: tools with unrecognized names.
// It actively tries all extraction strategies based on argument field shapes, in priority
// order, to infer what the tool does. Unlike augmentFromArgShape (Layer 2), this runs
// ONLY for unknown tools and sets the initial operation — Layer 2 can still upgrade it.
//
// Priority order:
//  1. Command field → shell AST parsing (highest signal)
//  2. URL field → host extraction + OpNetwork
//  3. Path + edit fields (old_string/new_string) → OpWrite
//  4. Path + content fields → OpWrite
//  5. Path only → OpRead
//
// All steps run unconditionally (no early returns) so multiple signals are merged.
func (e *Extractor) extractUnknownTool(info *ExtractedInfo) {
	// Step 1: Try shell AST parsing on any command-like field.
	// This catches tools like Cursor's run_terminal_cmd, Windsurf's "Run Command", etc.
	e.extractBashCommand(info)

	// Step 2: Extract hosts from URL-bearing fields.
	// This catches tools like Windsurf's "Read URL Content", MCP API tools, etc.
	// Handles both "https://evil.com/path" and scheme-less "evil.com/path".
	e.extractURLFields(info)

	// Step 3: Extract paths from known field names.
	e.extractPathFields(info)

	// Step 4: If paths were found, infer operation from accompanying fields.
	// Only infer when operation is still unknown — don't override explicit ops.
	if len(info.Paths) > 0 && info.Operation == OpNone {
		// Check for edit signals (old_string/new_string)
		_, hasOld := info.RawArgs["oldstring"]
		_, hasNew := info.RawArgs["newstring"]
		if hasOld || hasNew {
			info.addOperation(OpWrite)
		}

		// Check for write signals (content fields)
		if info.Operation == OpNone {
			for _, f := range knownContentFields {
				if _, ok := info.RawArgs[f]; ok {
					info.addOperation(OpWrite)
					break
				}
			}
		}

		// Path with no other signals = read
		if info.Operation == OpNone {
			info.addOperation(OpRead)
		}
	}

	// Extract content for content-matching rules
	e.extractContentField(info)
}

// augmentFromArgShape scans argument fields to detect tool intent regardless
// of tool name. This is Layer 2 (shape-based) defense — it always runs after
// the name-based Layer 1 to catch bypasses via renamed tools.
// It never downgrades the operation, only upgrades via operationPriority.
// It NEVER returns early — all steps always execute.
func (e *Extractor) augmentFromArgShape(info *ExtractedInfo) {
	// Step 1: If any command field present and not yet parsed → shell AST parse
	if info.Command == "" {
		for _, field := range knownCommandFields {
			if val, ok := info.RawArgs[field]; ok {
				if len(fieldStrings(val)) > 0 {
					e.extractBashCommand(info)
					break // found a command field, no need to check more
				}
			}
		}
		// DO NOT return — continue to check url/paths below
	}

	// Step 2: Check URL-bearing fields for host extraction
	// Handles both scheme-prefixed and scheme-less URLs.
	e.extractURLFields(info)

	// Step 3: Extract paths from known field names (additive)
	existingPaths := len(info.Paths)
	e.extractPathFields(info)
	newPathsFound := len(info.Paths) > existingPaths

	// Step 4: If paths exist, infer operation from field shape
	// Use operationPriority — only UPGRADE, never downgrade
	if len(info.Paths) > 0 {
		inferredOp := OpNone

		// Check for edit signals (old_string/new_string)
		_, hasOld := info.RawArgs["oldstring"]
		_, hasNew := info.RawArgs["newstring"]
		if hasOld || hasNew {
			inferredOp = OpWrite
		}

		// Check for write signals (content fields)
		if inferredOp == OpNone {
			for _, f := range knownContentFields {
				if _, ok := info.RawArgs[f]; ok {
					inferredOp = OpWrite
					break
				}
			}
		}

		// Path only with no other signals = read
		if inferredOp == OpNone && newPathsFound {
			inferredOp = OpRead
		}

		// Only upgrade, never downgrade (addOperation enforces this internally)
		if inferredOp != OpNone {
			info.addOperation(inferredOp)
		}
	}

	// SECURITY: Expand DNS rebinding hosts — services like nip.io and sslip.io
	// resolve arbitrary IPs (e.g., 127.0.0.1.nip.io → 127.0.0.1). Add the
	// embedded IP alongside the original hostname so IP-based host rules match.
	info.Hosts = expandRebindingHosts(info.Hosts)

	// Deduplicate
	info.Paths = deduplicateStrings(info.Paths)
	info.Hosts = deduplicateStrings(info.Hosts)
}

// extractWebFetchTool extracts info from WebFetch tool
func (e *Extractor) extractWebFetchTool(info *ExtractedInfo) {
	if val, ok := info.RawArgs["url"]; ok {
		for _, urlStr := range fieldStrings(val) {
			// SECURITY: file:// URLs are local reads, not network fetches.
			// Force OpRead so path-based rules catch file:// bypasses like
			// "WebFetch(url: file:///home/user/.ssh/id_rsa)".
			if p := extractPathFromFileURL(urlStr); p != "" {
				info.Paths = append(info.Paths, p)
				info.forceOperation(OpRead)
				continue
			}
			if host := extractHostFromURL(urlStr); host != "" {
				info.Hosts = append(info.Hosts, host)
				info.addOperation(OpNetwork)
			}
		}
	}
	// Default to OpNetwork if no URL was recognized
	if info.Operation == OpNone {
		info.addOperation(OpNetwork)
	}
}

// extractPathFromFileURL returns the local path from a file: URL.
// Handles all valid forms: file:///path, file://host/path, file:/path.
// Returns "" for non-file URLs or unparseable input.
func extractPathFromFileURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if strings.EqualFold(u.Scheme, "file") && u.Path != "" {
		// normalize // and .. in file: paths, then strip leading "/"
		// before Windows drive letters (e.g., "/C:/Users" → "C:/Users").
		return pathutil.StripFileURIDriveLetter(path.Clean(u.Path))
	}
	return ""
}

// extractPathFields extracts paths from known field names.
// Handles string values, []any arrays, and case-collision merged values.
func (e *Extractor) extractPathFields(info *ExtractedInfo) {
	for _, field := range knownPathFields {
		if val, ok := info.RawArgs[field]; ok {
			info.Paths = append(info.Paths, fieldStrings(val)...)
		}
	}
}

// extractURLFields extracts hosts from known URL field names.
// Handles string values, []any arrays, case-collision merged values, and scheme-less URLs.
func (e *Extractor) extractURLFields(info *ExtractedInfo) {
	for _, field := range knownURLFields {
		if val, ok := info.RawArgs[field]; ok {
			for _, u := range fieldStrings(val) {
				host := extractHostFromURLField(u)
				if host != "" {
					info.Hosts = append(info.Hosts, host)
					info.addOperation(OpNetwork)
				}
				// SECURITY: file:// URLs in any tool's URL field are local reads.
				// Without this, only recognized WebFetch tools get file:// extraction.
				if p := extractPathFromFileURL(u); p != "" {
					info.Paths = append(info.Paths, p)
					info.addOperation(OpRead)
				}
			}
		}
	}
}

// extractContentField extracts content from Write/Edit tool args.
// Handles string values, []any arrays (from case-collision merging), etc.
// For arrays, concatenates all string values so content-matching rules see everything.
func (e *Extractor) extractContentField(info *ExtractedInfo) {
	for _, field := range knownContentFields {
		if val, ok := info.RawArgs[field]; ok {
			if strs := fieldStrings(val); len(strs) > 0 {
				info.Content = strings.Join(strs, "\n")
				return
			}
		}
	}
}
