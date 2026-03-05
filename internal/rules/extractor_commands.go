package rules

import "strings"

// applyCommandSpecificExtraction handles command-specific argument analysis
// that cannot be expressed in the static commandDB. Called from
// extractFromParsedCommandsDepth after the generic path/host extraction.
func (e *Extractor) applyCommandSpecificExtraction(info *ExtractedInfo, cmdName string, args []string) {
	switch cmdName {
	case "scp", "rsync":
		extractScpRsyncHosts(info, args)
	case "socat":
		extractSocatAddresses(info, args)
	case "tar":
		extractTarMode(info, args)
	case "sed":
		extractSedInPlace(info, args)
	}
}

// extractScpRsyncHosts extracts hostnames from scp/rsync's user@host:path format.
// Standard extractHosts() misses these because they lack a URL scheme.
func extractScpRsyncHosts(info *ExtractedInfo, args []string) {
	for _, arg := range args {
		if host := extractScpHost(arg); host != "" {
			info.Hosts = append(info.Hosts, host)
		}
	}
}

// extractSocatAddresses parses socat's TYPE:param address arguments to detect
// operations and extract hosts/paths. Socat's address format differs from
// standard URLs: "TCP:host:port", "UNIX:/path", "EXEC:/bin/cmd".
//
// Address types handled:
//   - TCP/UDP/SSL/OPENSSL:host:port → OpNetwork + host extraction
//   - UNIX/ABSTRACT:path           → OpNetwork + socket path extraction
//   - EXEC/SYSTEM:cmd              → OpExecute
//   - OPEN/CREATE:path             → path extraction (OpRead already default)
func extractSocatAddresses(info *ExtractedInfo, args []string) {
	for _, arg := range args {
		if host := extractSocatHost(arg); host != "" {
			info.Hosts = append(info.Hosts, host)
			info.addOperation(OpNetwork)
			continue
		}
		argUpper := strings.ToUpper(arg)
		switch {
		case strings.HasPrefix(argUpper, "UNIX:") || strings.HasPrefix(argUpper, "UNIX4:") || strings.HasPrefix(argUpper, "UNIX6:"),
			strings.HasPrefix(argUpper, "ABSTRACT:"):
			// UNIX domain socket — extract path so path rules fire
			if _, sockPath, ok := strings.Cut(arg, ":"); ok && sockPath != "" {
				info.Paths = append(info.Paths, sockPath)
			}
			info.addOperation(OpNetwork)
		case strings.HasPrefix(argUpper, "EXEC:") || strings.HasPrefix(argUpper, "EXEC4:") || strings.HasPrefix(argUpper, "EXEC6:"),
			strings.HasPrefix(argUpper, "SYSTEM:"):
			info.addOperation(OpExecute)
		case strings.HasPrefix(argUpper, "OPEN:") || strings.HasPrefix(argUpper, "CREATE:"):
			if _, filePath, ok := strings.Cut(arg, ":"); ok && filePath != "" {
				info.Paths = append(info.Paths, filePath)
			}
		}
	}
}

// extractTarMode detects tar archive-creation mode (-c/--create) and upgrades
// the operation to OpWrite. Without this, "tar -czf out.tar.gz dir/" stays OpRead.
func extractTarMode(info *ExtractedInfo, args []string) {
	for _, arg := range args {
		if arg == "--create" {
			info.addOperation(OpWrite)
			return
		}
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg, "c") {
			info.addOperation(OpWrite)
			return
		}
	}
}

// extractSedInPlace detects sed in-place editing (-i, -i.bak, --in-place) and
// upgrades the operation to OpWrite. Without this, sed reads but never writes.
func extractSedInPlace(info *ExtractedInfo, args []string) {
	for _, arg := range args {
		if arg == "--in-place" || (strings.HasPrefix(arg, "-i") && !strings.HasPrefix(arg, "--")) {
			info.addOperation(OpWrite)
			return
		}
	}
}
