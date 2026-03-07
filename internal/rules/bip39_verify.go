//go:build ignore

// This program verifies BIP39 wordlist integrity against hardcoded SHA-512
// checksums from the canonical bitcoin/bips repository. Run via go generate.
package main

import (
	"crypto/sha512"
	"fmt"
	"os"
)

// SHA-512 checksums of canonical BIP39 wordlists from:
// https://github.com/bitcoin/bips/tree/master/bip-0039
var expected = map[string]string{
	"chinese_simplified.txt":  "f5b6d696a6b75bdeeacd0e0742d31eaa06cd683bb3c149052d82e0d47039534b23c82fc47fb193c86ff2b7c2b22f73ccc48cc500f09abc5e228998d9bc413ef7",
	"chinese_traditional.txt": "1e2689a48317a12a6b4a6a74de2241380fef57b250fafe6ab00a479db85d12661f8c33749240c9cec6535acd7f91e71dcba0bb8a27d1d32a3b76fe34797cad5b",
	"czech.txt":               "3d56a9d507b5b07a99b9d9924d8540944dd226d4b5050852027f09309a85513db2e57c9186f70b8f8226c342c28efcedd1e8edd507e1d39f8da693cfac0c39ca",
	"english.txt":             "416c71ba30018ea292bb36cdc23c9329673485a8d8933266a9d9a7cc72153b8baed3d430f52eab4f5d3addf6583611b3777a50454599f1e42716f5f879621123",
	"french.txt":              "001b2e7d1d17416776fa5306e4f7ec5812f3f35cc26fde46800a7dab1412870ac8b779b0c2fec1d75c24b80868e55bc5bfb88c8ded50c84040248b76a2c5332d",
	"italian.txt":             "d3dca24cf03f04eea1872d98c91748a8aa7aeac6e2c885a99f2d452904a75ffcf271506db369335726c0e3f7c8a6454935782586414b9affd2fe0eb004223da1",
	"japanese.txt":            "3faf87f7e48eb6635f7d7b18a34e7dacbc2c43a1cf6aa9c96015b2a3549710b8b7a0961e5d2e32d7e369099db89a874c4d761a8384fb558744c7f47ca8cb0772",
	"korean.txt":              "e645a1e0f26f2727a8fb7605d3b59668a670c9df04d07576fe473d844a23d0192020aedc286fbb9b1f64709ad30e6acb825803cf9f872954c1324aefd4977710",
	"portuguese.txt":          "0e6aa42870c6f9a77bda0931ea9423febffefbeb49e9dbda5fa732fc3479942629050517fef57bb1a76026195e16785186c0cfe26261c8fcc31f52fe69beda0f",
	"spanish.txt":             "0e838229265de6c80505088682d2dc9510147c3ab1713b556b594d09529b493cc3a7e391ad690dda2052d4e11c56572f8a215a7fffdb2630b13b4637329f3c31",
}

func main() {
	dir := "bip39"
	failed := 0
	for name, want := range expected {
		data, err := os.ReadFile(dir + "/" + name)
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
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d BIP39 wordlist(s) failed integrity check.\n", failed)
		fmt.Fprintf(os.Stderr, "Source: https://github.com/bitcoin/bips/tree/master/bip-0039\n")
		os.Exit(1)
	}
	fmt.Printf("ok: all %d BIP39 wordlists verified (SHA-512)\n", len(expected))
}
