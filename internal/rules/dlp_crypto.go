package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode"

	"github.com/BakeLens/crust/internal/pathutil"
	"github.com/btcsuite/btcd/btcutil/base58"
)

// Crypto DLP: detects cryptocurrency secrets using cryptographic validation.
// - BIP39 mnemonics: sliding window over embedded 2048-word English wordlist
// - Extended private keys (xprv/yprv/zprv/tprv): regex + base58check checksum
// - WIF private keys (5/K/L prefix): regex + base58check checksum + version byte
// - Wallet path protection: hardcoded directory check using OS-specific data dirs

// cryptoDLPMatch holds a crypto DLP detection result.
type cryptoDLPMatch struct {
	name    string
	message string
}

// scanCrypto checks content for cryptocurrency secrets.
// Returns the first match found, or nil if clean.
func scanCrypto(content string) *cryptoDLPMatch {
	if content == "" {
		return nil
	}
	if m := scanBIP39Mnemonic(content); m != nil {
		return m
	}
	if m := scanExtendedPrivateKey(content); m != nil {
		return m
	}
	if m := scanWIFKey(content); m != nil {
		return m
	}
	return nil
}

// --- BIP39 Mnemonic Detection ---

// bip39ValidLengths are the valid BIP39 mnemonic lengths.
var bip39ValidLengths = []int{12, 15, 18, 21, 24}

// scanBIP39Mnemonic detects BIP39 seed phrases using a sliding window.
// All 2048 words are embedded — no external dependency needed.
func scanBIP39Mnemonic(content string) *cryptoDLPMatch {
	// Extract lowercase words, filtering non-alpha tokens.
	words := extractLowerWords(content)
	if len(words) < 12 {
		return nil
	}

	for _, windowSize := range bip39ValidLengths {
		if len(words) < windowSize {
			break
		}
		for i := 0; i <= len(words)-windowSize; i++ {
			allMatch := true
			for j := range windowSize {
				if !bip39Wordlist[words[i+j]] {
					// Skip ahead: no point checking windows that include this non-BIP39 word.
					i += j
					allMatch = false
					break
				}
			}
			if allMatch {
				return &cryptoDLPMatch{
					name:    "builtin:dlp-crypto-bip39-mnemonic",
					message: "Cannot expose BIP39 mnemonic seed phrase — potential cryptocurrency key leak",
				}
			}
		}
	}
	return nil
}

// extractLowerWords splits content into lowercase alphabetic words.
func extractLowerWords(s string) []string {
	var words []string
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r)
	})
	for _, f := range fields {
		w := strings.ToLower(f)
		if len(w) >= 3 && len(w) <= 8 { // BIP39 words are 3-8 chars
			words = append(words, w)
		}
	}
	return words
}

// --- Extended Private Key Detection (xprv/yprv/zprv/tprv) ---

// xprvRegex matches base58-encoded extended private keys.
var xprvRegex = regexp.MustCompile(`[xyzt]prv[1-9A-HJ-NP-Za-km-z]{107,112}`)

// scanExtendedPrivateKey detects Bitcoin HD extended private keys with checksum validation.
func scanExtendedPrivateKey(content string) *cryptoDLPMatch {
	matches := xprvRegex.FindAllString(content, 5) // limit to 5 candidates
	for _, match := range matches {
		_, _, err := base58.CheckDecode(match)
		if err == nil {
			return &cryptoDLPMatch{
				name:    "builtin:dlp-crypto-xprv",
				message: "Cannot expose extended private key (xprv/yprv/zprv/tprv) — potential cryptocurrency key leak",
			}
		}
	}
	return nil
}

// --- WIF Private Key Detection ---

// wifRegex matches WIF-encoded Bitcoin private keys.
// Uncompressed: starts with 5, 51 chars total.
// Compressed: starts with K or L, 52 chars total.
var wifRegex = regexp.MustCompile(`[5KL][1-9A-HJ-NP-Za-km-z]{50,51}`)

// scanWIFKey detects Bitcoin WIF private keys with checksum + version byte validation.
func scanWIFKey(content string) *cryptoDLPMatch {
	matches := wifRegex.FindAllString(content, 5) // limit to 5 candidates
	for _, match := range matches {
		decoded, version, err := base58.CheckDecode(match)
		if err != nil {
			continue
		}
		// WIF version byte: 0x80 for mainnet, 0xEF for testnet.
		if version != 0x80 && version != 0xEF {
			continue
		}
		// WIF payload: 32 bytes (uncompressed) or 33 bytes (compressed, ends with 0x01).
		if len(decoded) == 32 || (len(decoded) == 33 && decoded[32] == 0x01) {
			return &cryptoDLPMatch{
				name:    "builtin:dlp-crypto-wif",
				message: "Cannot expose WIF private key — potential cryptocurrency key leak",
			}
		}
	}
	return nil
}

// --- Crypto Wallet Path Protection ---

// cryptoWalletDirs are computed once at init using OS-specific data directories.
// Checked after symlink resolution (step 10) so symlink bypasses are caught.
var cryptoWalletDirs []string

// cryptoDataDir returns the OS-specific data directory for a cryptocurrency.
// Follows the same convention as Bitcoin Core and most crypto wallets:
//   - Linux/FreeBSD: ~/.chainname  (lowercase, dot prefix)
//   - macOS:         ~/Library/Application Support/Chainname  (title case)
//   - Windows:       %LOCALAPPDATA%\Chainname  (title case)
func cryptoDataDir(home, chain string) string {
	upper := string(unicode.ToUpper(rune(chain[0]))) + chain[1:]
	lower := string(unicode.ToLower(rune(chain[0]))) + chain[1:]

	switch runtime.GOOS {
	case goosWindows:
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = os.Getenv("APPDATA")
		}
		if appData != "" {
			return filepath.Join(appData, upper)
		}
	case "darwin":
		if home != "" {
			return filepath.Join(home, "Library", "Application Support", upper)
		}
	default:
		if home != "" {
			return filepath.Join(home, "."+lower)
		}
	}
	return ""
}

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}

	// All major chains that follow the standard data directory convention.
	for _, chain := range []string{
		"bitcoin", "litecoin", "dogecoin", "dash", // Bitcoin forks
		"ethereum", "electrum", "monero", "zcash", // Major chains
		"cardano", "cosmos", "polkadot", // PoS chains
		"avalanche", "tron", // Other popular
	} {
		if dir := cryptoDataDir(home, chain); dir != "" {
			cryptoWalletDirs = append(cryptoWalletDirs, dir)
		}
	}

	// Solana (non-standard locations).
	if home != "" {
		cryptoWalletDirs = append(cryptoWalletDirs,
			filepath.Join(home, ".solana"),
			filepath.Join(home, ".config", "solana"),
		)
		// Sui, Aptos (newer chains with non-standard locations).
		cryptoWalletDirs = append(cryptoWalletDirs,
			filepath.Join(home, ".sui"),
			filepath.Join(home, ".aptos"),
		)
	}

	// Normalize wallet dirs: forward slashes + lowercase on case-insensitive
	// filesystems (NTFS, default APFS). hasCryptoWalletPath uses
	// pathutil.CleanPath which outputs forward slashes, so dirs must match.
	fs := pathutil.DefaultFS()
	for i, dir := range cryptoWalletDirs {
		cryptoWalletDirs[i] = fs.Lower(pathutil.ToSlash(dir))
	}
}

// hasCryptoWalletPath checks if any path is inside a crypto wallet directory.
// Defense-in-depth: lowercases cleaned paths on case-insensitive filesystems
// to match the lowered cryptoWalletDirs (set in init). This catches any paths
// that bypass the normalizer's lowering (e.g., symlink-resolved paths).
func hasCryptoWalletPath(paths []string) (bool, string) {
	fs := pathutil.DefaultFS()
	for _, p := range paths {
		cleaned := fs.Lower(pathutil.CleanPath(p))
		for _, dir := range cryptoWalletDirs {
			if pathutil.HasPathPrefix(cleaned, dir) {
				return true, p
			}
		}
	}
	return false, ""
}

// --- Embedded BIP39 English Wordlist (2048 words) ---
// Source: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt

var bip39Wordlist = map[string]bool{
	"abandon": true, "ability": true, "able": true, "about": true, "above": true,
	"absent": true, "absorb": true, "abstract": true, "absurd": true, "abuse": true,
	"access": true, "accident": true, "account": true, "accuse": true, "achieve": true,
	"acid": true, "acoustic": true, "acquire": true, "across": true, "act": true,
	"action": true, "actor": true, "actress": true, "actual": true, "adapt": true,
	"add": true, "addict": true, "address": true, "adjust": true, "admit": true,
	"adult": true, "advance": true, "advice": true, "aerobic": true, "affair": true,
	"afford": true, "afraid": true, "again": true, "age": true, "agent": true,
	"agree": true, "ahead": true, "aim": true, "air": true, "airport": true,
	"aisle": true, "alarm": true, "album": true, "alcohol": true, "alert": true,
	"alien": true, "all": true, "alley": true, "allow": true, "almost": true,
	"alone": true, "alpha": true, "already": true, "also": true, "alter": true,
	"always": true, "amateur": true, "amazing": true, "among": true, "amount": true,
	"amused": true, "analyst": true, "anchor": true, "ancient": true, "anger": true,
	"angle": true, "angry": true, "animal": true, "ankle": true, "announce": true,
	"annual": true, "another": true, "answer": true, "antenna": true, "antique": true,
	"anxiety": true, "any": true, "apart": true, "apology": true, "appear": true,
	"apple": true, "approve": true, "april": true, "arch": true, "arctic": true,
	"area": true, "arena": true, "argue": true, "arm": true, "armed": true,
	"armor": true, "army": true, "around": true, "arrange": true, "arrest": true,
	"arrive": true, "arrow": true, "art": true, "artefact": true, "artist": true, //nolint:misspell // official BIP39 word
	"artwork": true, "ask": true, "aspect": true, "assault": true, "asset": true,
	"assist": true, "assume": true, "asthma": true, "athlete": true, "atom": true,
	"attack": true, "attend": true, "attitude": true, "attract": true, "auction": true,
	"audit": true, "august": true, "aunt": true, "author": true, "auto": true,
	"autumn": true, "average": true, "avocado": true, "avoid": true, "awake": true,
	"aware": true, "away": true, "awesome": true, "awful": true, "awkward": true,
	"axis": true, "baby": true, "bachelor": true, "bacon": true, "badge": true,
	"bag": true, "balance": true, "balcony": true, "ball": true, "bamboo": true,
	"banana": true, "banner": true, "bar": true, "barely": true, "bargain": true,
	"barrel": true, "base": true, "basic": true, "basket": true, "battle": true,
	"beach": true, "bean": true, "beauty": true, "because": true, "become": true,
	"beef": true, "before": true, "begin": true, "behave": true, "behind": true,
	"believe": true, "below": true, "belt": true, "bench": true, "benefit": true,
	"best": true, "betray": true, "better": true, "between": true, "beyond": true,
	"bicycle": true, "bid": true, "bike": true, "bind": true, "biology": true,
	"bird": true, "birth": true, "bitter": true, "black": true, "blade": true,
	"blame": true, "blanket": true, "blast": true, "bleak": true, "bless": true,
	"blind": true, "blood": true, "blossom": true, "blouse": true, "blue": true,
	"blur": true, "blush": true, "board": true, "boat": true, "body": true,
	"boil": true, "bomb": true, "bone": true, "bonus": true, "book": true,
	"boost": true, "border": true, "boring": true, "borrow": true, "boss": true,
	"bottom": true, "bounce": true, "box": true, "boy": true, "bracket": true,
	"brain": true, "brand": true, "brass": true, "brave": true, "bread": true,
	"breeze": true, "brick": true, "bridge": true, "brief": true, "bright": true,
	"bring": true, "brisk": true, "broccoli": true, "broken": true, "bronze": true,
	"broom": true, "brother": true, "brown": true, "brush": true, "bubble": true,
	"buddy": true, "budget": true, "buffalo": true, "build": true, "bulb": true,
	"bulk": true, "bullet": true, "bundle": true, "bunker": true, "burden": true,
	"burger": true, "burst": true, "bus": true, "business": true, "busy": true,
	"butter": true, "buyer": true, "buzz": true, "cabbage": true, "cabin": true,
	"cable": true, "cactus": true, "cage": true, "cake": true, "call": true,
	"calm": true, "camera": true, "camp": true, "can": true, "canal": true,
	"cancel": true, "candy": true, "cannon": true, "canoe": true, "canvas": true,
	"canyon": true, "capable": true, "capital": true, "captain": true, "car": true,
	"carbon": true, "card": true, "cargo": true, "carpet": true, "carry": true,
	"cart": true, "case": true, "cash": true, "casino": true, "castle": true,
	"casual": true, "cat": true, "catalog": true, "catch": true, "category": true,
	"cattle": true, "caught": true, "cause": true, "caution": true, "cave": true,
	"ceiling": true, "celery": true, "cement": true, "census": true, "century": true,
	"cereal": true, "certain": true, "chair": true, "chalk": true, "champion": true,
	"change": true, "chaos": true, "chapter": true, "charge": true, "chase": true,
	"chat": true, "cheap": true, "check": true, "cheese": true, "chef": true,
	"cherry": true, "chest": true, "chicken": true, "chief": true, "child": true,
	"chimney": true, "choice": true, "choose": true, "chronic": true, "chuckle": true,
	"chunk": true, "churn": true, "cigar": true, "cinnamon": true, "circle": true,
	"citizen": true, "city": true, "civil": true, "claim": true, "clap": true,
	"clarify": true, "claw": true, "clay": true, "clean": true, "clerk": true,
	"clever": true, "click": true, "client": true, "cliff": true, "climb": true,
	"clinic": true, "clip": true, "clock": true, "clog": true, "close": true,
	"cloth": true, "cloud": true, "clown": true, "club": true, "clump": true,
	"cluster": true, "clutch": true, "coach": true, "coast": true, "coconut": true,
	"code": true, "coffee": true, "coil": true, "coin": true, "collect": true,
	"color": true, "column": true, "combine": true, "come": true, "comfort": true,
	"comic": true, "common": true, "company": true, "concert": true, "conduct": true,
	"confirm": true, "congress": true, "connect": true, "consider": true, "control": true,
	"convince": true, "cook": true, "cool": true, "copper": true, "copy": true,
	"coral": true, "core": true, "corn": true, "correct": true, "cost": true,
	"cotton": true, "couch": true, "country": true, "couple": true, "course": true,
	"cousin": true, "cover": true, "coyote": true, "crack": true, "cradle": true,
	"craft": true, "cram": true, "crane": true, "crash": true, "crater": true,
	"crawl": true, "crazy": true, "cream": true, "credit": true, "creek": true,
	"crew": true, "cricket": true, "crime": true, "crisp": true, "critic": true,
	"crop": true, "cross": true, "crouch": true, "crowd": true, "crucial": true,
	"cruel": true, "cruise": true, "crumble": true, "crunch": true, "crush": true,
	"cry": true, "crystal": true, "cube": true, "culture": true, "cup": true,
	"cupboard": true, "curious": true, "current": true, "curtain": true, "curve": true,
	"cushion": true, "custom": true, "cute": true, "cycle": true, "dad": true,
	"damage": true, "damp": true, "dance": true, "danger": true, "daring": true,
	"dash": true, "daughter": true, "dawn": true, "day": true, "deal": true,
	"debate": true, "debris": true, "decade": true, "december": true, "decide": true,
	"decline": true, "decorate": true, "decrease": true, "deer": true, "defense": true,
	"define": true, "defy": true, "degree": true, "delay": true, "deliver": true,
	"demand": true, "demise": true, "denial": true, "dentist": true, "deny": true,
	"depart": true, "depend": true, "deposit": true, "depth": true, "deputy": true,
	"derive": true, "describe": true, "desert": true, "design": true, "desk": true,
	"despair": true, "destroy": true, "detail": true, "detect": true, "develop": true,
	"device": true, "devote": true, "diagram": true, "dial": true, "diamond": true,
	"diary": true, "dice": true, "diesel": true, "diet": true, "differ": true,
	"digital": true, "dignity": true, "dilemma": true, "dinner": true, "dinosaur": true,
	"direct": true, "dirt": true, "disagree": true, "discover": true, "disease": true,
	"dish": true, "dismiss": true, "disorder": true, "display": true, "distance": true,
	"divert": true, "divide": true, "divorce": true, "dizzy": true, "doctor": true,
	"document": true, "dog": true, "doll": true, "dolphin": true, "domain": true,
	"donate": true, "donkey": true, "donor": true, "door": true, "dose": true,
	"double": true, "dove": true, "draft": true, "dragon": true, "drama": true,
	"drastic": true, "draw": true, "dream": true, "dress": true, "drift": true,
	"drill": true, "drink": true, "drip": true, "drive": true, "drop": true,
	"drum": true, "dry": true, "duck": true, "dumb": true, "dune": true,
	"during": true, "dust": true, "dutch": true, "duty": true, "dwarf": true,
	"dynamic": true, "eager": true, "eagle": true, "early": true, "earn": true,
	"earth": true, "easily": true, "east": true, "easy": true, "echo": true,
	"ecology": true, "economy": true, "edge": true, "edit": true, "educate": true,
	"effort": true, "egg": true, "eight": true, "either": true, "elbow": true,
	"elder": true, "electric": true, "elegant": true, "element": true, "elephant": true,
	"elevator": true, "elite": true, "else": true, "embark": true, "embody": true,
	"embrace": true, "emerge": true, "emotion": true, "employ": true, "empower": true,
	"empty": true, "enable": true, "enact": true, "end": true, "endless": true,
	"endorse": true, "enemy": true, "energy": true, "enforce": true, "engage": true,
	"engine": true, "enhance": true, "enjoy": true, "enlist": true, "enough": true,
	"enrich": true, "enroll": true, "ensure": true, "enter": true, "entire": true,
	"entry": true, "envelope": true, "episode": true, "equal": true, "equip": true,
	"era": true, "erase": true, "erode": true, "erosion": true, "error": true,
	"erupt": true, "escape": true, "essay": true, "essence": true, "estate": true,
	"eternal": true, "ethics": true, "evidence": true, "evil": true, "evoke": true,
	"evolve": true, "exact": true, "example": true, "excess": true, "exchange": true,
	"excite": true, "exclude": true, "excuse": true, "execute": true, "exercise": true,
	"exhaust": true, "exhibit": true, "exile": true, "exist": true, "exit": true,
	"exotic": true, "expand": true, "expect": true, "expire": true, "explain": true,
	"expose": true, "express": true, "extend": true, "extra": true, "eye": true,
	"eyebrow": true, "fabric": true, "face": true, "faculty": true, "fade": true,
	"faint": true, "faith": true, "fall": true, "false": true, "fame": true,
	"family": true, "famous": true, "fan": true, "fancy": true, "fantasy": true,
	"farm": true, "fashion": true, "fat": true, "fatal": true, "father": true,
	"fatigue": true, "fault": true, "favorite": true, "feature": true, "february": true,
	"federal": true, "fee": true, "feed": true, "feel": true, "female": true,
	"fence": true, "festival": true, "fetch": true, "fever": true, "few": true,
	"fiber": true, "fiction": true, "field": true, "figure": true, "file": true,
	"film": true, "filter": true, "final": true, "find": true, "fine": true,
	"finger": true, "finish": true, "fire": true, "firm": true, "first": true,
	"fiscal": true, "fish": true, "fit": true, "fitness": true, "fix": true,
	"flag": true, "flame": true, "flash": true, "flat": true, "flavor": true,
	"flee": true, "flight": true, "flip": true, "float": true, "flock": true,
	"floor": true, "flower": true, "fluid": true, "flush": true, "fly": true,
	"foam": true, "focus": true, "fog": true, "foil": true, "fold": true,
	"follow": true, "food": true, "foot": true, "force": true, "forest": true,
	"forget": true, "fork": true, "fortune": true, "forum": true, "forward": true,
	"fossil": true, "foster": true, "found": true, "fox": true, "fragile": true,
	"frame": true, "frequent": true, "fresh": true, "friend": true, "fringe": true,
	"frog": true, "front": true, "frost": true, "frown": true, "frozen": true,
	"fruit": true, "fuel": true, "fun": true, "funny": true, "furnace": true,
	"fury": true, "future": true, "gadget": true, "gain": true, "galaxy": true,
	"gallery": true, "game": true, "gap": true, "garage": true, "garbage": true,
	"garden": true, "garlic": true, "garment": true, "gas": true, "gasp": true,
	"gate": true, "gather": true, "gauge": true, "gaze": true, "general": true,
	"genius": true, "genre": true, "gentle": true, "genuine": true, "gesture": true,
	"ghost": true, "giant": true, "gift": true, "giggle": true, "ginger": true,
	"giraffe": true, "girl": true, "give": true, "glad": true, "glance": true,
	"glare": true, "glass": true, "glide": true, "glimpse": true, "globe": true,
	"gloom": true, "glory": true, "glove": true, "glow": true, "glue": true,
	"goat": true, "goddess": true, "gold": true, "good": true, "goose": true,
	"gorilla": true, "gospel": true, "gossip": true, "govern": true, "gown": true,
	"grab": true, "grace": true, "grain": true, "grant": true, "grape": true,
	"grass": true, "gravity": true, "great": true, "green": true, "grid": true,
	"grief": true, "grit": true, "grocery": true, "group": true, "grow": true,
	"grunt": true, "guard": true, "guess": true, "guide": true, "guilt": true,
	"guitar": true, "gun": true, "gym": true, "habit": true, "hair": true,
	"half": true, "hammer": true, "hamster": true, "hand": true, "happy": true,
	"harbor": true, "hard": true, "harsh": true, "harvest": true, "hat": true,
	"have": true, "hawk": true, "hazard": true, "head": true, "health": true,
	"heart": true, "heavy": true, "hedgehog": true, "height": true, "hello": true,
	"helmet": true, "help": true, "hen": true, "hero": true, "hidden": true,
	"high": true, "hill": true, "hint": true, "hip": true, "hire": true,
	"history": true, "hobby": true, "hockey": true, "hold": true, "hole": true,
	"holiday": true, "hollow": true, "home": true, "honey": true, "hood": true,
	"hope": true, "horn": true, "horror": true, "horse": true, "hospital": true,
	"host": true, "hotel": true, "hour": true, "hover": true, "hub": true,
	"huge": true, "human": true, "humble": true, "humor": true, "hundred": true,
	"hungry": true, "hunt": true, "hurdle": true, "hurry": true, "hurt": true,
	"husband": true, "hybrid": true, "ice": true, "icon": true, "idea": true,
	"identify": true, "idle": true, "ignore": true, "ill": true, "illegal": true,
	"illness": true, "image": true, "imitate": true, "immense": true, "immune": true,
	"impact": true, "impose": true, "improve": true, "impulse": true, "inch": true,
	"include": true, "income": true, "increase": true, "index": true, "indicate": true,
	"indoor": true, "industry": true, "infant": true, "inflict": true, "inform": true,
	"inhale": true, "inherit": true, "initial": true, "inject": true, "injury": true,
	"inmate": true, "inner": true, "innocent": true, "input": true, "inquiry": true,
	"insane": true, "insect": true, "inside": true, "inspire": true, "install": true,
	"intact": true, "interest": true, "into": true, "invest": true, "invite": true,
	"involve": true, "iron": true, "island": true, "isolate": true, "issue": true,
	"item": true, "ivory": true, "jacket": true, "jaguar": true, "jar": true,
	"jazz": true, "jealous": true, "jeans": true, "jelly": true, "jewel": true,
	"job": true, "join": true, "joke": true, "journey": true, "joy": true,
	"judge": true, "juice": true, "jump": true, "jungle": true, "junior": true,
	"junk": true, "just": true, "kangaroo": true, "keen": true, "keep": true,
	"ketchup": true, "key": true, "kick": true, "kid": true, "kidney": true,
	"kind": true, "kingdom": true, "kiss": true, "kit": true, "kitchen": true,
	"kite": true, "kitten": true, "kiwi": true, "knee": true, "knife": true,
	"knock": true, "know": true, "lab": true, "label": true, "labor": true,
	"ladder": true, "lady": true, "lake": true, "lamp": true, "language": true,
	"laptop": true, "large": true, "later": true, "latin": true, "laugh": true,
	"laundry": true, "lava": true, "law": true, "lawn": true, "lawsuit": true,
	"layer": true, "lazy": true, "leader": true, "leaf": true, "learn": true,
	"leave": true, "lecture": true, "left": true, "leg": true, "legal": true,
	"legend": true, "leisure": true, "lemon": true, "lend": true, "length": true,
	"lens": true, "leopard": true, "lesson": true, "letter": true, "level": true,
	"liar": true, "liberty": true, "library": true, "license": true, "life": true,
	"lift": true, "light": true, "like": true, "limb": true, "limit": true,
	"link": true, "lion": true, "liquid": true, "list": true, "little": true,
	"live": true, "lizard": true, "load": true, "loan": true, "lobster": true,
	"local": true, "lock": true, "logic": true, "lonely": true, "long": true,
	"loop": true, "lottery": true, "loud": true, "lounge": true, "love": true,
	"loyal": true, "lucky": true, "luggage": true, "lumber": true, "lunar": true,
	"lunch": true, "luxury": true, "lyrics": true, "machine": true, "mad": true,
	"magic": true, "magnet": true, "maid": true, "mail": true, "main": true,
	"major": true, "make": true, "mammal": true, "man": true, "manage": true,
	"mandate": true, "mango": true, "mansion": true, "manual": true, "maple": true,
	"marble": true, "march": true, "margin": true, "marine": true, "market": true,
	"marriage": true, "mask": true, "mass": true, "master": true, "match": true,
	"material": true, "math": true, "matrix": true, "matter": true, "maximum": true,
	"maze": true, "meadow": true, "mean": true, "measure": true, "meat": true,
	"mechanic": true, "medal": true, "media": true, "melody": true, "melt": true,
	"member": true, "memory": true, "mention": true, "menu": true, "mercy": true,
	"merge": true, "merit": true, "merry": true, "mesh": true, "message": true,
	"metal": true, "method": true, "middle": true, "midnight": true, "milk": true,
	"million": true, "mimic": true, "mind": true, "minimum": true, "minor": true,
	"minute": true, "miracle": true, "mirror": true, "misery": true, "miss": true,
	"mistake": true, "mix": true, "mixed": true, "mixture": true, "mobile": true,
	"model": true, "modify": true, "mom": true, "moment": true, "monitor": true,
	"monkey": true, "monster": true, "month": true, "moon": true, "moral": true,
	"more": true, "morning": true, "mosquito": true, "mother": true, "motion": true,
	"motor": true, "mountain": true, "mouse": true, "move": true, "movie": true,
	"much": true, "muffin": true, "mule": true, "multiply": true, "muscle": true,
	"museum": true, "mushroom": true, "music": true, "must": true, "mutual": true,
	"myself": true, "mystery": true, "myth": true, "naive": true, "name": true,
	"napkin": true, "narrow": true, "nasty": true, "nation": true, "nature": true,
	"near": true, "neck": true, "need": true, "negative": true, "neglect": true,
	"neither": true, "nephew": true, "nerve": true, "nest": true, "net": true,
	"network": true, "neutral": true, "never": true, "news": true, "next": true,
	"nice": true, "night": true, "noble": true, "noise": true, "nominee": true,
	"noodle": true, "normal": true, "north": true, "nose": true, "notable": true,
	"note": true, "nothing": true, "notice": true, "novel": true, "now": true,
	"nuclear": true, "number": true, "nurse": true, "nut": true, "oak": true,
	"obey": true, "object": true, "oblige": true, "obscure": true, "observe": true,
	"obtain": true, "obvious": true, "occur": true, "ocean": true, "october": true,
	"odor": true, "off": true, "offer": true, "office": true, "often": true,
	"oil": true, "okay": true, "old": true, "olive": true, "olympic": true,
	"omit": true, "once": true, "one": true, "onion": true, "online": true,
	"only": true, "open": true, "opera": true, "opinion": true, "oppose": true,
	"option": true, "orange": true, "orbit": true, "orchard": true, "order": true,
	"ordinary": true, "organ": true, "orient": true, "original": true, "orphan": true,
	"ostrich": true, "other": true, "outdoor": true, "outer": true, "output": true,
	"outside": true, "oval": true, "oven": true, "over": true, "own": true,
	"owner": true, "oxygen": true, "oyster": true, "ozone": true, "pact": true,
	"paddle": true, "page": true, "pair": true, "palace": true, "palm": true,
	"panda": true, "panel": true, "panic": true, "panther": true, "paper": true,
	"parade": true, "parent": true, "park": true, "parrot": true, "party": true,
	"pass": true, "patch": true, "path": true, "patient": true, "patrol": true,
	"pattern": true, "pause": true, "pave": true, "payment": true, "peace": true,
	"peanut": true, "pear": true, "peasant": true, "pelican": true, "pen": true,
	"penalty": true, "pencil": true, "people": true, "pepper": true, "perfect": true,
	"permit": true, "person": true, "pet": true, "phone": true, "photo": true,
	"phrase": true, "physical": true, "piano": true, "picnic": true, "picture": true,
	"piece": true, "pig": true, "pigeon": true, "pill": true, "pilot": true,
	"pink": true, "pioneer": true, "pipe": true, "pistol": true, "pitch": true,
	"pizza": true, "place": true, "planet": true, "plastic": true, "plate": true,
	"play": true, "please": true, "pledge": true, "pluck": true, "plug": true,
	"plunge": true, "poem": true, "poet": true, "point": true, "polar": true,
	"pole": true, "police": true, "pond": true, "pony": true, "pool": true,
	"popular": true, "portion": true, "position": true, "possible": true, "post": true,
	"potato": true, "pottery": true, "poverty": true, "powder": true, "power": true,
	"practice": true, "praise": true, "predict": true, "prefer": true, "prepare": true,
	"present": true, "pretty": true, "prevent": true, "price": true, "pride": true,
	"primary": true, "print": true, "priority": true, "prison": true, "private": true,
	"prize": true, "problem": true, "process": true, "produce": true, "profit": true,
	"program": true, "project": true, "promote": true, "proof": true, "property": true,
	"prosper": true, "protect": true, "proud": true, "provide": true, "public": true,
	"pudding": true, "pull": true, "pulp": true, "pulse": true, "pumpkin": true,
	"punch": true, "pupil": true, "puppy": true, "purchase": true, "purity": true,
	"purpose": true, "purse": true, "push": true, "put": true, "puzzle": true,
	"pyramid": true, "quality": true, "quantum": true, "quarter": true, "question": true,
	"quick": true, "quit": true, "quiz": true, "quote": true, "rabbit": true,
	"raccoon": true, "race": true, "rack": true, "radar": true, "radio": true,
	"rail": true, "rain": true, "raise": true, "rally": true, "ramp": true,
	"ranch": true, "random": true, "range": true, "rapid": true, "rare": true,
	"rate": true, "rather": true, "raven": true, "raw": true, "razor": true,
	"ready": true, "real": true, "reason": true, "rebel": true, "rebuild": true,
	"recall": true, "receive": true, "recipe": true, "record": true, "recycle": true,
	"reduce": true, "reflect": true, "reform": true, "refuse": true, "region": true,
	"regret": true, "regular": true, "reject": true, "relax": true, "release": true,
	"relief": true, "rely": true, "remain": true, "remember": true, "remind": true,
	"remove": true, "render": true, "renew": true, "rent": true, "reopen": true,
	"repair": true, "repeat": true, "replace": true, "report": true, "require": true,
	"rescue": true, "resemble": true, "resist": true, "resource": true, "response": true,
	"result": true, "retire": true, "retreat": true, "return": true, "reunion": true,
	"reveal": true, "review": true, "reward": true, "rhythm": true, "rib": true,
	"ribbon": true, "rice": true, "rich": true, "ride": true, "ridge": true,
	"rifle": true, "right": true, "rigid": true, "ring": true, "riot": true,
	"ripple": true, "risk": true, "ritual": true, "rival": true, "river": true,
	"road": true, "roast": true, "robot": true, "robust": true, "rocket": true,
	"romance": true, "roof": true, "rookie": true, "room": true, "rose": true,
	"rotate": true, "rough": true, "round": true, "route": true, "royal": true,
	"rubber": true, "rude": true, "rug": true, "rule": true, "run": true,
	"runway": true, "rural": true, "sad": true, "saddle": true, "sadness": true,
	"safe": true, "sail": true, "salad": true, "salmon": true, "salon": true,
	"salt": true, "salute": true, "same": true, "sample": true, "sand": true,
	"satisfy": true, "satoshi": true, "sauce": true, "sausage": true, "save": true,
	"say": true, "scale": true, "scan": true, "scare": true, "scatter": true,
	"scene": true, "scheme": true, "school": true, "science": true, "scissors": true,
	"scorpion": true, "scout": true, "scrap": true, "screen": true, "script": true,
	"scrub": true, "sea": true, "search": true, "season": true, "seat": true,
	"second": true, "secret": true, "section": true, "security": true, "seed": true,
	"seek": true, "segment": true, "select": true, "sell": true, "seminar": true,
	"senior": true, "sense": true, "sentence": true, "series": true, "service": true,
	"session": true, "settle": true, "setup": true, "seven": true, "shadow": true,
	"shaft": true, "shallow": true, "share": true, "shed": true, "shell": true,
	"sheriff": true, "shield": true, "shift": true, "shine": true, "ship": true,
	"shiver": true, "shock": true, "shoe": true, "shoot": true, "shop": true,
	"short": true, "shoulder": true, "shove": true, "shrimp": true, "shrug": true,
	"shuffle": true, "shy": true, "sibling": true, "sick": true, "side": true,
	"siege": true, "sight": true, "sign": true, "silent": true, "silk": true,
	"silly": true, "silver": true, "similar": true, "simple": true, "since": true,
	"sing": true, "siren": true, "sister": true, "situate": true, "six": true,
	"size": true, "skate": true, "sketch": true, "ski": true, "skill": true,
	"skin": true, "skirt": true, "skull": true, "slab": true, "slam": true,
	"sleep": true, "slender": true, "slice": true, "slide": true, "slight": true,
	"slim": true, "slogan": true, "slot": true, "slow": true, "slush": true,
	"small": true, "smart": true, "smile": true, "smoke": true, "smooth": true,
	"snack": true, "snake": true, "snap": true, "sniff": true, "snow": true,
	"soap": true, "soccer": true, "social": true, "sock": true, "soda": true,
	"soft": true, "solar": true, "soldier": true, "solid": true, "solution": true,
	"solve": true, "someone": true, "song": true, "soon": true, "sorry": true,
	"sort": true, "soul": true, "sound": true, "soup": true, "source": true,
	"south": true, "space": true, "spare": true, "spatial": true, "spawn": true,
	"speak": true, "special": true, "speed": true, "spell": true, "spend": true,
	"sphere": true, "spice": true, "spider": true, "spike": true, "spin": true,
	"spirit": true, "split": true, "spoil": true, "sponsor": true, "spoon": true,
	"sport": true, "spot": true, "spray": true, "spread": true, "spring": true,
	"spy": true, "square": true, "squeeze": true, "squirrel": true, "stable": true,
	"stadium": true, "staff": true, "stage": true, "stairs": true, "stamp": true,
	"stand": true, "start": true, "state": true, "stay": true, "steak": true,
	"steel": true, "stem": true, "step": true, "stereo": true, "stick": true,
	"still": true, "sting": true, "stock": true, "stomach": true, "stone": true,
	"stool": true, "story": true, "stove": true, "strategy": true, "street": true,
	"strike": true, "strong": true, "struggle": true, "student": true, "stuff": true,
	"stumble": true, "style": true, "subject": true, "submit": true, "subway": true,
	"success": true, "such": true, "sudden": true, "suffer": true, "sugar": true,
	"suggest": true, "suit": true, "summer": true, "sun": true, "sunny": true,
	"sunset": true, "super": true, "supply": true, "supreme": true, "sure": true,
	"surface": true, "surge": true, "surprise": true, "surround": true, "survey": true,
	"suspect": true, "sustain": true, "swallow": true, "swamp": true, "swap": true,
	"swarm": true, "swear": true, "sweet": true, "swift": true, "swim": true,
	"swing": true, "switch": true, "sword": true, "symbol": true, "symptom": true,
	"syrup": true, "system": true, "table": true, "tackle": true, "tag": true,
	"tail": true, "talent": true, "talk": true, "tank": true, "tape": true,
	"target": true, "task": true, "taste": true, "tattoo": true, "taxi": true,
	"teach": true, "team": true, "tell": true, "ten": true, "tenant": true,
	"tennis": true, "tent": true, "term": true, "test": true, "text": true,
	"thank": true, "that": true, "theme": true, "then": true, "theory": true,
	"there": true, "they": true, "thing": true, "this": true, "thought": true,
	"three": true, "thrive": true, "throw": true, "thumb": true, "thunder": true,
	"ticket": true, "tide": true, "tiger": true, "tilt": true, "timber": true,
	"time": true, "tiny": true, "tip": true, "tired": true, "tissue": true,
	"title": true, "toast": true, "tobacco": true, "today": true, "toddler": true,
	"toe": true, "together": true, "toilet": true, "token": true, "tomato": true,
	"tomorrow": true, "tone": true, "tongue": true, "tonight": true, "tool": true,
	"tooth": true, "top": true, "topic": true, "topple": true, "torch": true,
	"tornado": true, "tortoise": true, "toss": true, "total": true, "tourist": true,
	"toward": true, "tower": true, "town": true, "toy": true, "track": true,
	"trade": true, "traffic": true, "tragic": true, "train": true, "transfer": true,
	"trap": true, "trash": true, "travel": true, "tray": true, "treat": true,
	"tree": true, "trend": true, "trial": true, "tribe": true, "trick": true,
	"trigger": true, "trim": true, "trip": true, "trophy": true, "trouble": true,
	"truck": true, "true": true, "truly": true, "trumpet": true, "trust": true,
	"truth": true, "try": true, "tube": true, "tuition": true, "tumble": true,
	"tuna": true, "tunnel": true, "turkey": true, "turn": true, "turtle": true,
	"twelve": true, "twenty": true, "twice": true, "twin": true, "twist": true,
	"two": true, "type": true, "typical": true, "ugly": true, "umbrella": true,
	"unable": true, "unaware": true, "uncle": true, "uncover": true, "under": true,
	"undo": true, "unfair": true, "unfold": true, "unhappy": true, "uniform": true,
	"unique": true, "unit": true, "universe": true, "unknown": true, "unlock": true,
	"until": true, "unusual": true, "unveil": true, "update": true, "upgrade": true,
	"uphold": true, "upon": true, "upper": true, "upset": true, "urban": true,
	"urge": true, "usage": true, "use": true, "used": true, "useful": true,
	"useless": true, "usual": true, "utility": true, "vacant": true, "vacuum": true,
	"vague": true, "valid": true, "valley": true, "valve": true, "van": true,
	"vanish": true, "vapor": true, "various": true, "vast": true, "vault": true,
	"vehicle": true, "velvet": true, "vendor": true, "venture": true, "venue": true,
	"verb": true, "verify": true, "version": true, "very": true, "vessel": true,
	"veteran": true, "viable": true, "vibrant": true, "vicious": true, "victory": true,
	"video": true, "view": true, "village": true, "vintage": true, "violin": true,
	"virtual": true, "virus": true, "visa": true, "visit": true, "visual": true,
	"vital": true, "vivid": true, "vocal": true, "voice": true, "void": true,
	"volcano": true, "volume": true, "vote": true, "voyage": true, "wage": true,
	"wagon": true, "wait": true, "walk": true, "wall": true, "walnut": true,
	"want": true, "warfare": true, "warm": true, "warrior": true, "wash": true,
	"wasp": true, "waste": true, "water": true, "wave": true, "way": true,
	"wealth": true, "weapon": true, "wear": true, "weasel": true, "weather": true,
	"web": true, "wedding": true, "weekend": true, "weird": true, "welcome": true,
	"west": true, "wet": true, "whale": true, "what": true, "wheat": true,
	"wheel": true, "when": true, "where": true, "whip": true, "whisper": true,
	"wide": true, "width": true, "wife": true, "wild": true, "will": true,
	"win": true, "window": true, "wine": true, "wing": true, "wink": true,
	"winner": true, "winter": true, "wire": true, "wisdom": true, "wise": true,
	"wish": true, "witness": true, "wolf": true, "woman": true, "wonder": true,
	"wood": true, "wool": true, "word": true, "work": true, "world": true,
	"worry": true, "worth": true, "wrap": true, "wreck": true, "wrestle": true,
	"wrist": true, "write": true, "wrong": true, "yard": true, "year": true,
	"yellow": true, "you": true, "young": true, "youth": true, "zebra": true,
	"zero": true, "zone": true, "zoo": true,
}
