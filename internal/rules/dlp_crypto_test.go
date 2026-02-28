package rules

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// BIP32 test vector 1 — well-known master extended private key.
const testXprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

// Known WIF private key from Bitcoin wiki (uncompressed, mainnet).
const testWIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"

// Standard BIP39 12-word test mnemonic.
const testMnemonic12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// Standard BIP39 15-word test mnemonic.
const testMnemonic15 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// Standard BIP39 18-word test mnemonic.
const testMnemonic18 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// Standard BIP39 24-word test mnemonic.
const testMnemonic24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

func TestCryptoDLPDetection(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantNil bool
		wantID  string
	}{
		// --- BIP39 Mnemonic Detection ---
		{
			name:    "12-word BIP39 mnemonic",
			content: testMnemonic12,
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "24-word BIP39 mnemonic",
			content: testMnemonic24,
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "15-word BIP39 mnemonic",
			content: testMnemonic15,
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "18-word BIP39 mnemonic",
			content: testMnemonic18,
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "mnemonic embedded in code",
			content: `const seed = "` + testMnemonic12 + `"`,
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "mnemonic with surrounding text",
			content: "Here is my wallet backup: " + testMnemonic12 + " — keep this safe!",
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "mnemonic with newlines between words",
			content: strings.ReplaceAll(testMnemonic12, " ", "\n"),
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},

		// --- Extended Private Key Detection ---
		{
			name:    "xprv key (BIP32 test vector 1)",
			content: testXprv,
			wantID:  "builtin:dlp-crypto-xprv",
		},
		{
			name:    "xprv embedded in JSON",
			content: `{"master_key": "` + testXprv + `"}`,
			wantID:  "builtin:dlp-crypto-xprv",
		},

		// --- WIF Key Detection ---
		{
			name:    "WIF key (uncompressed)",
			content: testWIF,
			wantID:  "builtin:dlp-crypto-wif",
		},
		{
			name:    "WIF key embedded in config",
			content: "PRIVATE_KEY=" + testWIF,
			wantID:  "builtin:dlp-crypto-wif",
		},

		// --- No Detection (clean content) ---
		{
			name:    "empty content",
			content: "",
			wantNil: true,
		},
		{
			name:    "normal English text",
			content: "The quick brown fox jumps over the lazy dog.",
			wantNil: true,
		},
		{
			name:    "Go source code",
			content: `func main() { fmt.Println("hello world") }`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanCrypto(tt.content)
			if tt.wantNil {
				if result != nil {
					t.Errorf("scanCrypto() = %q, want nil", result.name)
				}
				return
			}
			if result == nil {
				t.Fatal("scanCrypto() = nil, want match")
			}
			if result.name != tt.wantID {
				t.Errorf("scanCrypto().name = %q, want %q", result.name, tt.wantID)
			}
			if result.message == "" {
				t.Error("scanCrypto().message is empty")
			}
		})
	}
}

func TestCryptoDLPFalsePositives(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "11 BIP39 words (below minimum)",
			content: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
		},
		{
			name:    "12 common English words (not all BIP39)",
			content: "the quick brown fox jumps over the lazy dog near the house",
		},
		{
			name:    "xprv-like string with bad checksum",
			content: "xprvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			name:    "random K-prefixed string (not valid WIF)",
			content: "KzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzZ",
		},
		{
			name:    "base58 alphabet soup",
			content: "5" + strings.Repeat("1", 50),
		},
		{
			name:    "xprv in variable name only",
			content: `var xprvKeyPath = "/some/path"`,
		},
		{
			name:    "Bitcoin address (not a private key)",
			content: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		},
		{
			name:    "words from BIP39 mixed with non-BIP39",
			content: "abandon ability xylophone microphone telephone abandon ability xylophone microphone telephone abandon ability",
		},
		{
			name:    "short WIF-like prefix in URL",
			content: "https://example.com/5K/path/to/resource",
		},
		{
			name:    "code with abandon in comments",
			content: "// We should abandon this approach and start over with a new design pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanCrypto(tt.content)
			if result != nil {
				t.Errorf("scanCrypto() = %q, want nil (false positive)", result.name)
			}
		})
	}
}

func TestCryptoWalletPaths(t *testing.T) {
	// Verify that cryptoWalletDirs was populated at init.
	if len(cryptoWalletDirs) == 0 {
		t.Fatal("cryptoWalletDirs is empty — init() failed")
	}

	// Should contain at least bitcoin and ethereum.
	hasBitcoin := false
	hasEthereum := false
	for _, dir := range cryptoWalletDirs {
		lower := strings.ToLower(dir)
		if strings.Contains(lower, "bitcoin") {
			hasBitcoin = true
		}
		if strings.Contains(lower, "ethereum") {
			hasEthereum = true
		}
	}
	if !hasBitcoin {
		t.Error("cryptoWalletDirs missing bitcoin directory")
	}
	if !hasEthereum {
		t.Error("cryptoWalletDirs missing ethereum directory")
	}

	// Test hasCryptoWalletPath.
	t.Run("direct access", func(t *testing.T) {
		// Use the first wallet dir as test target.
		testDir := cryptoWalletDirs[0]
		testPath := filepath.Join(testDir, "wallet.dat")

		blocked, path := hasCryptoWalletPath([]string{testPath})
		if !blocked {
			t.Errorf("hasCryptoWalletPath(%q) = false, want true", testPath)
		}
		if path != testPath {
			t.Errorf("matched path = %q, want %q", path, testPath)
		}
	})

	t.Run("unrelated path", func(t *testing.T) {
		blocked, _ := hasCryptoWalletPath([]string{"/tmp/safe/file.txt"})
		if blocked {
			t.Error("hasCryptoWalletPath(/tmp/safe/file.txt) = true, want false")
		}
	})

	t.Run("directory itself", func(t *testing.T) {
		testDir := cryptoWalletDirs[0]
		blocked, _ := hasCryptoWalletPath([]string{testDir})
		if !blocked {
			t.Errorf("hasCryptoWalletPath(%q) = false, want true (directory itself)", testDir)
		}
	})
}

func TestCryptoWalletPathsOSSpecific(t *testing.T) {
	// Verify paths follow OS conventions via btcutil.AppDataDir.
	switch runtime.GOOS {
	case "darwin":
		// macOS: ~/Library/Application Support/Bitcoin
		found := false
		for _, dir := range cryptoWalletDirs {
			if strings.Contains(dir, "Library/Application Support") && strings.Contains(dir, "itcoin") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("macOS: expected Library/Application Support path for Bitcoin, got: %v", cryptoWalletDirs)
		}
	case "linux":
		// Linux: ~/.bitcoin
		found := false
		for _, dir := range cryptoWalletDirs {
			if strings.Contains(dir, ".bitcoin") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Linux: expected .bitcoin path, got: %v", cryptoWalletDirs)
		}
	}
}

func TestBIP39WordlistCount(t *testing.T) {
	if len(bip39Wordlist) != 2048 {
		t.Errorf("bip39Wordlist has %d words, want 2048", len(bip39Wordlist))
	}
}
