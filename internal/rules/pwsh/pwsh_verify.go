//go:build ignore

// This program verifies PowerShell bootstrap script integrity against hardcoded
// SHA-512 checksums and scans for suspicious patterns. Run via go generate.
package main

import (
	"crypto/sha512"
	"fmt"
	"os"
	"strings"
)

var expected = map[string]string{
	"ps_bootstrap_header.ps1": "8c08fbf7b8b587d41cd73c8144c62a50f4d628605e61bfd0cf4bff3e9b6fcd23bfc2fbedfbc01a4ed2e1d01435f18de6aa164a5029e247ad62e3f2b0f4d5edcd",
	"ps_bootstrap_vars.ps1":   "86ff1f37556cbdc1cf7dc555ba4a85e5297de838012e1adb45611bb5b56b924e6406aed08b8ffdf2f00c724ac22288a7af0e360a61470849515a2f360d917cc0",
	"ps_bootstrap_cmds.ps1":   "0fbfc650deb3e54e3d6396dab403f9ec158b80aa175c98199d876f1a30ad733f521e2784e540ba993d48fb88108c3455f994d80a3631ada1af2fbac511ef48ec",
	"ps_bootstrap_dotnet.ps1": "e860692428a3881b0386b39a3c36492a9edb5792b150495de6187f902522dad30b2a84f709e65a28d8f34b3048b9ef63cfe1a2dcf3094d6e7c65f04d4e6f8223",
	"ps_bootstrap_footer.ps1": "6aae27c5bae8c5ce550e14438ffdbd5ec2b0df54e8183bff6cfe354ca10db7511437fb312eb22ca36ce0c5570515360c02529f07038bb53b6def39f9df1123ed",
}

// Suspicious patterns that should never appear in bootstrap scripts.
// These indicate code injection or exfiltration capabilities.
var suspicious = []string{
	"Invoke-Expression",
	"IEX ",
	"IEX(",
	"Start-Process",
	"New-Object Net.WebClient",
	"DownloadString",
	"DownloadFile",
	"Invoke-WebRequest",
	"Invoke-RestMethod",
	"[System.Net.WebClient]",
	"bitstransfer",
}

func main() {
	failed := 0

	// 1. SHA-512 checksums
	for name, want := range expected {
		data, err := os.ReadFile(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", name, err)
			failed++
			continue
		}
		got := fmt.Sprintf("%x", sha512.Sum512(data))
		if got != want {
			fmt.Fprintf(os.Stderr, "FAIL: %s: SHA-512 mismatch\n  got:  %s\n  want: %s\n", name, got, want)
			failed++
		}
	}

	// 2. Suspicious pattern scan across all scripts
	for name := range expected {
		data, err := os.ReadFile(name)
		if err != nil {
			continue // already reported above
		}
		content := strings.ToLower(string(data))
		for _, pat := range suspicious {
			if strings.Contains(content, strings.ToLower(pat)) {
				fmt.Fprintf(os.Stderr, "FAIL: %s: contains suspicious pattern %q\n", name, pat)
				failed++
			}
		}
	}

	// 3. Verify ConvertTo-Json is present in footer (required for JSON output)
	footer, err := os.ReadFile("ps_bootstrap_footer.ps1")
	if err == nil && !strings.Contains(string(footer), "ConvertTo-Json") {
		fmt.Fprintf(os.Stderr, "FAIL: ps_bootstrap_footer.ps1: missing ConvertTo-Json (required for JSON output)\n")
		failed++
	}

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d PowerShell bootstrap integrity check(s) failed.\n", failed)
		os.Exit(1)
	}
	fmt.Printf("ok: all %d PowerShell bootstrap scripts verified (SHA-512 + pattern scan)\n", len(expected))
}
