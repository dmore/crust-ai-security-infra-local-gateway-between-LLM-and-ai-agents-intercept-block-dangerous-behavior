#!/bin/bash
#
# Shared shell functions for the Crust installer.
# Sourced by install.sh.
#

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Plain mode: set when NO_COLOR is set or stdout is not a TTY.
# Matches the Go TUI's IsPlainMode() logic.
if [ -n "${NO_COLOR:-}" ] || [ "${CI:-}" = "true" ] || [ ! -t 1 ]; then
    _PLAIN=1
else
    _PLAIN=0
fi

# ─── Icons (Unicode BMP — same set as internal/tui/icons.go) ─────────────────
ICON_CHECK="✔"    # U+2714
ICON_CROSS="✖"    # U+2716
ICON_WARN="⚠"     # U+26A0
ICON_INFO="ℹ"     # U+2139
ICON_DIAMOND="◆"  # U+25C6  (brand prefix)

# ─── Configuration ────────────────────────────────────────────────────────────
GITHUB_REPO="BakeLens/crust"
INSTALL_DIR="$HOME/.local/bin"
BINARY_NAME="crust"
DATA_DIR="$HOME/.crust"
GO_MIN_VERSION="1.26.1"
GO_DL_BASE="https://dl.google.com/go"

# ─── Step counter & progress bar ─────────────────────────────────────────────
_STEP_N=0
_STEP_TOTAL=0
_BAR_WIDTH=20

init_steps() {
    _STEP_TOTAL="$1"
    _STEP_N=0
}

# Print a numbered step header with inline progress bar.
# Usage: step "Label"
step() {
    _STEP_N=$((_STEP_N + 1))
    if [ "$_PLAIN" = "1" ]; then
        echo ""
        echo "[$_STEP_N/$_STEP_TOTAL] $1"
        return
    fi
    local filled=$(( _STEP_N * _BAR_WIDTH / _STEP_TOTAL ))
    local empty=$(( _BAR_WIDTH - filled ))
    local bar="" i
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty;  i++)); do bar+="░"; done
    local pct=$(( _STEP_N * 100 / _STEP_TOTAL ))
    echo ""
    echo -e "${BLUE}${ICON_DIAMOND}${NC} ${BOLD}[$_STEP_N/$_STEP_TOTAL]${NC} $1  ${DIM}${bar} ${pct}%${NC}"
}

# ─── Output helpers ───────────────────────────────────────────────────────────

ok() {
    if [ "$_PLAIN" = "1" ]; then echo "    OK  $*"; else
        echo -e "    ${GREEN}${ICON_CHECK}${NC}  $*"; fi
}

fail() {
    if [ "$_PLAIN" = "1" ]; then echo "    ERR $*" >&2; else
        echo -e "    ${RED}${ICON_CROSS}${NC}  $*" >&2; fi
    exit 1
}

warn() {
    if [ "$_PLAIN" = "1" ]; then echo "    WRN $*"; else
        echo -e "    ${YELLOW}${ICON_WARN}${NC}  $*"; fi
}

info() {
    if [ "$_PLAIN" = "1" ]; then echo "    ... $*"; else
        echo -e "    ${CYAN}${ICON_INFO}${NC}  $*"; fi
}

print_bold() {
    if [ "$_PLAIN" = "1" ]; then echo "$*"; else echo -e "${BOLD}$*${NC}"; fi
}

# ─── Spinner (TTY only; plain mode prints a static dot line) ─────────────────
_SPINNER_PID=""

spinner_start() {
    if [ "$_PLAIN" = "1" ]; then
        echo "    ... $1..."
        return
    fi
    local msg="$1"
    (
        trap 'exit 0' TERM
        local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
        local i=0
        while true; do
            printf "\r    \033[34m%s\033[0m  %s..." "${frames[$(( i % 10 ))]}" "$msg"
            i=$(( i + 1 ))
            sleep 0.08
        done
    ) &
    _SPINNER_PID=$!
}

spinner_stop() {
    if [ -n "${_SPINNER_PID:-}" ]; then
        kill "$_SPINNER_PID" 2>/dev/null || true
        wait "$_SPINNER_PID" 2>/dev/null || true
        _SPINNER_PID=""
        [ "$_PLAIN" = "0" ] && printf "\r\033[K"
    fi
}

spinner_ok()   { spinner_stop; ok "$1"; }
spinner_warn() { spinner_stop; warn "$1"; }
spinner_fail() { spinner_stop; fail "$1"; }

# ─── Platform detection ───────────────────────────────────────────────────────

# Returns: darwin | linux | freebsd | unsupported
detect_os() {
    case "$(uname -s)" in
        Darwin)  echo "darwin"  ;;
        Linux)   echo "linux"   ;;
        FreeBSD) echo "freebsd" ;;
        *)       echo "unsupported" ;;
    esac
}

# Returns: amd64 | arm64 | unsupported
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "amd64" ;;
        arm64|aarch64) echo "arm64" ;;
        *)             echo "unsupported" ;;
    esac
}

# Sets OS_NAME and ARCH_NAME globals; exits on unsupported platform.
detect_platform() {
    OS_NAME=$(detect_os)
    ARCH_NAME=$(detect_arch)

    if [ "$OS_NAME" = "unsupported" ]; then
        fail "Unsupported OS: $(uname -s). Crust supports macOS, Linux, and FreeBSD."
    fi
    if [ "$ARCH_NAME" = "unsupported" ]; then
        fail "Unsupported architecture: $(uname -m). Crust supports amd64 and arm64."
    fi
    ok "OS: ${OS_NAME}  ·  Arch: ${ARCH_NAME}"
}

# ─── Go version helpers ───────────────────────────────────────────────────────

_go_current_version() {
    go version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1
}

# Returns 0 if installed Go meets GO_MIN_VERSION (1.26.1).
_go_version_ok() {
    command -v go &>/dev/null || return 1
    local ver; ver=$(_go_current_version)
    local maj min pat
    IFS='.' read -r maj min pat <<< "$ver"
    pat="${pat:-0}"
    [ "$maj" -gt 1 ] && return 0
    [ "$maj" -eq 1 ] && [ "$min" -gt 26 ] && return 0
    [ "$maj" -eq 1 ] && [ "$min" -eq 26 ] && [ "$pat" -ge 1 ] && return 0
    return 1
}

# ─── Dependency auto-install ──────────────────────────────────────────────────

# Download and extract Go tarball from go.dev into $HOME/.local/go (no sudo needed).
_install_go_tarball() {
    local os_name="$1" arch_name="$2"
    local tarball="go${GO_MIN_VERSION}.${os_name}-${arch_name}.tar.gz"
    local url="${GO_DL_BASE}/${tarball}"
    local tmp; tmp=$(mktemp -t crust-go-XXXXXX.tar.gz)

    spinner_start "Downloading Go ${GO_MIN_VERSION}"
    if ! download "$url" "$tmp"; then
        rm -f "$tmp"
        spinner_fail "Go download failed — install from https://go.dev/dl/"
    fi
    spinner_ok "Download complete"

    info "Extracting to ${HOME}/.local/go"
    mkdir -p "${HOME}/.local"
    rm -rf "${HOME}/.local/go"
    tar -C "${HOME}/.local" -xzf "$tmp"
    rm -f "$tmp"

    export PATH="${HOME}/.local/go/bin:${PATH}"
    ok "Go $(_go_current_version) installed to ~/.local/go"
    warn "Add to your shell config: export PATH=\"\$HOME/.local/go/bin:\$PATH\""
}

# Ensure Go >= GO_MIN_VERSION is available; auto-installs if missing or outdated.
ensure_go() {
    if _go_version_ok; then
        ok "Go $(_go_current_version)"
        return 0
    fi

    if command -v go &>/dev/null; then
        warn "Go $(_go_current_version) found — ${GO_MIN_VERSION}+ required, upgrading"
    else
        info "Go not found — installing ${GO_MIN_VERSION}"
    fi

    case "$OS_NAME" in
        darwin)
            if command -v brew &>/dev/null; then
                spinner_start "Installing Go via Homebrew"
                if brew install go >/dev/null 2>&1 || brew upgrade go >/dev/null 2>&1; then
                    eval "$(brew shellenv 2>/dev/null)" || true
                    if _go_version_ok; then
                        spinner_ok "Go $(_go_current_version) installed via Homebrew"
                        return 0
                    fi
                fi
                spinner_warn "Homebrew install failed — trying direct download"
            fi
            _install_go_tarball "$OS_NAME" "$ARCH_NAME"
            ;;
        linux)
            # Alpine: apk community ships a recent Go — try first, fall back if too old
            if command -v apk &>/dev/null; then
                spinner_start "Installing Go via apk"
                if apk add --no-cache go >/dev/null 2>&1; then
                    spinner_stop
                    if _go_version_ok; then
                        ok "Go $(_go_current_version) installed via apk"
                        return 0
                    fi
                    warn "apk provided Go $(_go_current_version) — ${GO_MIN_VERSION}+ required, upgrading via direct download"
                else
                    spinner_warn "apk install failed — trying direct download"
                fi
            # snap usually has a current release; apt/dnf ship outdated versions
            elif command -v snap &>/dev/null; then
                spinner_start "Installing Go via snap"
                if snap install go --classic >/dev/null 2>&1; then
                    export PATH="/snap/bin:${PATH}"
                    if _go_version_ok; then
                        spinner_ok "Go $(_go_current_version) installed via snap"
                        return 0
                    fi
                fi
                spinner_warn "snap install failed — trying direct download"
            fi
            _install_go_tarball "$OS_NAME" "$ARCH_NAME"
            ;;
        freebsd)
            # FreeBSD ports may ship Go 1.25 — try pkg first, fall back if too old
            spinner_start "Installing Go via pkg"
            if sudo pkg install -y go >/dev/null 2>&1; then
                spinner_stop
                if _go_version_ok; then
                    ok "Go $(_go_current_version) installed via pkg"
                    return 0
                fi
                warn "pkg provided Go $(_go_current_version) — ${GO_MIN_VERSION}+ required, upgrading via direct download"
            else
                spinner_warn "pkg install failed — trying direct download"
            fi
            _install_go_tarball "$OS_NAME" "$ARCH_NAME"
            ;;
    esac

    _go_version_ok || fail "Go ${GO_MIN_VERSION}+ required. Install from https://go.dev/dl/"
}

# Ensure git is available; auto-installs via system package manager.
ensure_git() {
    if command -v git &>/dev/null; then
        ok "git $(git --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
        return 0
    fi

    info "git not found — installing"

    case "$OS_NAME" in
        darwin)
            if command -v brew &>/dev/null; then
                spinner_start "Installing git via Homebrew"
                if brew install git >/dev/null 2>&1; then
                    spinner_ok "git installed via Homebrew"
                    return 0
                fi
                spinner_warn "Homebrew install failed"
            fi
            info "Triggering Xcode Command Line Tools installer (includes git)..."
            xcode-select --install 2>/dev/null || true
            warn "Complete the Xcode CLT installation, then re-run this installer."
            exit 1
            ;;
        linux)
            if command -v apk &>/dev/null; then
                spinner_start "Installing git via apk"
                apk add --no-cache git >/dev/null 2>&1 && spinner_ok "git installed" && return 0
                spinner_warn "apk install failed"
            elif command -v apt-get &>/dev/null; then
                spinner_start "Installing git via apt"
                sudo apt-get install -y git >/dev/null 2>&1 && spinner_ok "git installed" && return 0
                spinner_warn "apt install failed"
            elif command -v dnf &>/dev/null; then
                spinner_start "Installing git via dnf"
                sudo dnf install -y git >/dev/null 2>&1 && spinner_ok "git installed" && return 0
                spinner_warn "dnf install failed"
            elif command -v pacman &>/dev/null; then
                spinner_start "Installing git via pacman"
                sudo pacman -Sy --noconfirm git >/dev/null 2>&1 && spinner_ok "git installed" && return 0
                spinner_warn "pacman install failed"
            elif command -v zypper &>/dev/null; then
                spinner_start "Installing git via zypper"
                sudo zypper install -y git >/dev/null 2>&1 && spinner_ok "git installed" && return 0
                spinner_warn "zypper install failed"
            fi
            fail "Cannot install git automatically. Run: apk add git  (or your distro's equivalent)"
            ;;
        freebsd)
            spinner_start "Installing git via pkg"
            sudo pkg install -y git >/dev/null 2>&1 && spinner_ok "git installed" && return 0
            spinner_fail "Cannot install git. Run: sudo pkg install git"
            ;;
    esac
}

# Ensure curl or wget is available; auto-installs curl if missing.
ensure_download_tool() {
    command -v curl &>/dev/null || command -v wget &>/dev/null && return 0

    info "curl/wget not found — installing curl"

    case "$OS_NAME" in
        darwin)
            # curl ships with macOS
            fail "curl not found on macOS — please check your system."
            ;;
        linux)
            if command -v apk &>/dev/null; then
                apk add --no-cache curl >/dev/null 2>&1 && ok "curl installed" && return 0
            elif command -v apt-get &>/dev/null; then
                sudo apt-get install -y curl >/dev/null 2>&1 && ok "curl installed" && return 0
            elif command -v dnf &>/dev/null; then
                sudo dnf install -y curl >/dev/null 2>&1 && ok "curl installed" && return 0
            elif command -v pacman &>/dev/null; then
                sudo pacman -Sy --noconfirm curl >/dev/null 2>&1 && ok "curl installed" && return 0
            elif command -v zypper &>/dev/null; then
                sudo zypper install -y curl >/dev/null 2>&1 && ok "curl installed" && return 0
            fi
            fail "Cannot install curl. Run: apk add curl  (or your distro's equivalent)"
            ;;
        freebsd)
            sudo pkg install -y curl >/dev/null 2>&1 && ok "curl installed" && return 0
            fail "Cannot install curl. Run: sudo pkg install curl"
            ;;
    esac
}

# Check requirements: always ensures git + download tool; pass "go" for Go check.
check_requirements() {
    ensure_download_tool
    ensure_git
    for req in "$@"; do
        case "$req" in
            go) ensure_go ;;
            *)
                if ! command -v "$req" &>/dev/null; then
                    fail "Required tool '$req' not found. Install it and try again."
                fi
                ok "$req"
                ;;
        esac
    done
}

# ─── Download ─────────────────────────────────────────────────────────────────

download() {
    local url="$1" output="$2"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O "$output"
    fi
}

# ─── GitHub version resolution ────────────────────────────────────────────────

get_latest_version() {
    local url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local version
    if command -v curl &>/dev/null; then
        version=$(curl -fsSL "$url" 2>/dev/null | grep '"tag_name"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget &>/dev/null; then
        version=$(wget -qO- "$url" 2>/dev/null | grep '"tag_name"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    fi
    echo "${version:-main}"
}

resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        spinner_start "Fetching latest version"
        VERSION=$(get_latest_version)
        spinner_ok "Version ${VERSION}"
    else
        ok "Version ${VERSION}"
    fi
}

# ─── Banner ───────────────────────────────────────────────────────────────────
# Block-art logo matching internal/tui/banner/banner.go logoLines.

print_banner() {
    local edition="${1:-}"
    echo ""
    if [ "$_PLAIN" = "1" ]; then
        echo "CRUST - Secure Gateway for AI Agents${edition:+ [$edition]}"
    else
        echo -e "${YELLOW}${BOLD}▄███▄  ████▄  █   █  ▄███▄  █████${NC}"
        echo -e "${YELLOW}${BOLD}█      █   █  █   █  █        █   ${NC}"
        echo -e "${YELLOW}${BOLD}█      ████▀  █   █  ▀███▄    █   ${NC}"
        echo -e "${YELLOW}${BOLD}█      █  █   █   █      █    █   ${NC}"
        echo -e "${YELLOW}${BOLD}▀███▀  █   █  ▀███▀  ▀███▀    █   ${NC}"
        echo ""
        if [ -n "$edition" ]; then
            echo -e "  ${BLUE}Secure Gateway for AI Agents${NC}  ${BOLD}[$edition]${NC}"
        else
            echo -e "  ${BLUE}Secure Gateway for AI Agents${NC}"
        fi
    fi
    echo ""
}

# ─── Repository & build ───────────────────────────────────────────────────────

# Clone the repo into target_dir at the given version tag.
clone_repo() {
    local version="$1" target="$2"
    spinner_start "Cloning repository"
    if git clone --depth 1 --branch "$version" "https://github.com/${GITHUB_REPO}.git" "$target" >/dev/null 2>&1; then
        spinner_ok "Repository cloned"
    elif git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$target" >/dev/null 2>&1; then
        spinner_ok "Repository cloned (main branch)"
    else
        spinner_fail "Clone failed — check your internet connection"
    fi
}

# Build the Go binary. Uses BUILD_TAGS global if set (e.g. "notui").
build_go_binary() {
    local src_dir="$1" version="$2"
    local tags_flag=""
    if [ -n "${BUILD_TAGS:-}" ]; then
        tags_flag="-tags ${BUILD_TAGS}"
        spinner_start "Building Crust (${BUILD_TAGS})"
    else
        spinner_start "Building Crust"
    fi
    cd "$src_dir" || return 1
    go fix ./... >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    if go build ${tags_flag} -ldflags "-X main.Version=${version#v}" -o crust . >/dev/null 2>&1; then
        spinner_ok "Build complete"
    else
        spinner_fail "Build failed"
    fi
}

# Move built binary to INSTALL_DIR.
install_go_binary() {
    local src_dir="$1"
    mkdir -p "$INSTALL_DIR"
    mv "$src_dir/crust" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    ok "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
}

# ─── Post-install setup ───────────────────────────────────────────────────────

setup_data_dir() {
    mkdir -p "$DATA_DIR" "$DATA_DIR/rules.d"
    ok "Data directory: ${DATA_DIR}"
}

setup_completion() {
    if "$INSTALL_DIR/$BINARY_NAME" completion --install >/dev/null 2>&1; then
        ok "Shell completion installed — restart your shell to activate"
    else
        warn "Shell completion skipped (non-fatal)"
    fi
}

# Install gitleaks for DLP Tier 2 secret detection (200+ patterns).
setup_gitleaks() {
    if command -v gitleaks &>/dev/null; then
        ok "gitleaks already installed"
        return 0
    fi

    local os; os="$(uname -s)"
    if [ "$os" = "Darwin" ] && command -v brew &>/dev/null; then
        spinner_start "Installing gitleaks via Homebrew"
        if brew install gitleaks >/dev/null 2>&1; then
            spinner_ok "gitleaks installed via Homebrew"
            return 0
        fi
        spinner_warn "Homebrew install failed — trying go install"
    fi

    spinner_start "Installing gitleaks via go install"
    # Install directly into INSTALL_DIR so it lands on PATH alongside crust.
    if GOBIN="$INSTALL_DIR" go install github.com/zricethezav/gitleaks/v8@v8.30.0 >/dev/null 2>&1; then
        spinner_ok "gitleaks installed"
        return 0
    fi
    spinner_warn "gitleaks install failed (DLP Tier 2 will be disabled)"
    info "Install manually: go install github.com/zricethezav/gitleaks/v8@v8.30.0"
}

# Install Cascadia Mono NF from Nerd Fonts (optional, non-fatal).
# Skipped with --no-font or --no-tui flags.
setup_font() {
    if [ -n "${SKIP_FONT:-}" ]; then return 0; fi

    local nf_version="v3.3.0"
    local font_url="https://github.com/ryanoasis/nerd-fonts/releases/download/${nf_version}/CascadiaMono.zip"
    local font_dir os; os="$(uname -s)"
    case "$os" in
        Darwin) font_dir="$HOME/Library/Fonts" ;;
        Linux)  font_dir="$HOME/.local/share/fonts" ;;
        *)      warn "Font install skipped (unsupported OS)"; return 0 ;;
    esac

    if ls "$font_dir"/CascadiaMono*NF*.ttf &>/dev/null 2>&1; then
        ok "Cascadia Mono NF already installed"
        return 0
    fi

    local tmp_zip; tmp_zip=$(mktemp -t crust-font-XXXXXX.zip)
    spinner_start "Downloading Cascadia Mono NF"
    if ! download "$font_url" "$tmp_zip"; then
        spinner_warn "Font download failed (non-fatal)"
        rm -f "$tmp_zip"; return 0
    fi
    spinner_ok "Font downloaded"

    mkdir -p "$font_dir"
    if unzip -o -j "$tmp_zip" "*.ttf" -d "$font_dir" &>/dev/null; then
        ok "Font installed to ${font_dir}"
    else
        warn "Font extraction failed (non-fatal)"
    fi
    rm -f "$tmp_zip"

    if [ "$os" = "Linux" ] && command -v fc-cache &>/dev/null; then
        fc-cache -f "$font_dir" >/dev/null 2>&1 || true
    fi
}

# Print PATH hint if crust is not yet on PATH.
setup_path_hint() {
    if ! command -v crust &>/dev/null; then
        echo ""
        warn "crust is not on your PATH yet"
        echo ""
        echo "    Add to your shell config:"
        echo ""
        echo "      echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
        echo "      source ~/.bashrc"
        echo ""
    fi
}

# ─── Argument parsing ─────────────────────────────────────────────────────────

# Sets VERSION, BUILD_TAGS, DO_UNINSTALL, SKIP_FONT globals.
parse_args() {
    VERSION="latest"
    BUILD_TAGS=""
    DO_UNINSTALL=""
    DO_PURGE=""
    SKIP_FONT=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version|-v)
                VERSION="$2"
                shift 2
                ;;
            --no-tui)
                BUILD_TAGS="notui"
                SKIP_FONT="1"
                shift
                ;;
            --no-font)
                SKIP_FONT="1"
                shift
                ;;
            --uninstall)
                # shellcheck disable=SC2034
                DO_UNINSTALL="1"
                shift
                ;;
            --purge)
                # shellcheck disable=SC2034
                DO_UNINSTALL="1"
                # shellcheck disable=SC2034
                DO_PURGE="1"
                shift
                ;;
            --help|-h)
                echo "Crust Installer"
                echo ""
                echo "Options:"
                echo "  --version, -v    Install specific version or branch (e.g. v2.0.0, main)"
                echo "  --no-tui         Build without TUI dependencies (plain text only)"
                echo "  --no-font        Skip Nerd Font installation"
                echo "  --uninstall      Uninstall crust (keeps rules, config, secrets, DB)"
                echo "  --purge          Uninstall crust and delete all data including DB"
                echo "  --help, -h       Show this help"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# ─── Uninstall ────────────────────────────────────────────────────────────────

# Uninstall crust. Pass optional extra paths to remove.
run_uninstall() {
    print_banner ""
    print_bold "Uninstalling Crust..."
    echo ""

    if command -v crust &>/dev/null; then
        spinner_start "Stopping crust"
        crust stop >/dev/null 2>&1 || true
        spinner_ok "crust stopped"
    fi

    local crust_bin="$INSTALL_DIR/$BINARY_NAME"
    if [ -x "$crust_bin" ]; then
        spinner_start "Removing shell completion"
        "$crust_bin" completion --uninstall >/dev/null 2>&1 || true
        spinner_ok "Shell completion removed"
    fi

    if [ -f "$crust_bin" ]; then
        rm -f "$crust_bin"
        ok "Binary removed: $crust_bin"
    fi

    for extra in "$@"; do
        if [ -e "$extra" ]; then
            rm -rf "$extra"
            ok "Removed: $extra"
        fi
    done

    if [ -d "$DATA_DIR" ]; then
        echo ""

        # ── Runtime files (always removed silently) ───────────────────────────
        rm -f "$DATA_DIR/crust.pid" "$DATA_DIR/crust.port" "$DATA_DIR/crust.log"
        rm -f "$DATA_DIR"/crust-api-*.sock

        # ── Telemetry database (purge=delete, interactive=prompt, else keep) ────
        if [ -f "$DATA_DIR/crust.db" ]; then
            local confirm_db=""
            if [ "${DO_PURGE:-}" = "1" ]; then
                confirm_db="y"
            elif [ "$_PLAIN" = "0" ]; then
                echo -e "  ${YELLOW}Remove telemetry database ($DATA_DIR/crust.db)?${NC}"
                echo "  This contains your request history and security event data."
                read -r -p "  Remove? [y/N] " confirm_db
            fi
            if [[ "$confirm_db" =~ ^[Yy]$ ]]; then
                rm -f "$DATA_DIR/crust.db"
                ok "Telemetry database removed"
            else
                info "Database kept: $DATA_DIR/crust.db"
            fi
        fi

        # ── User data (always kept) ───────────────────────────────────────────
        # rules.d  — user-authored security rules
        # config.yaml — user configuration
        # secrets.json — stored API keys
        if [ -f "$DATA_DIR/config.yaml" ]; then
            info "Config kept:  $DATA_DIR/config.yaml"
        fi
        if [ -f "$DATA_DIR/secrets.json" ]; then
            info "Secrets kept: $DATA_DIR/secrets.json"
        fi
        if [ -d "$DATA_DIR/rules.d" ] && [ -n "$(ls -A "$DATA_DIR/rules.d" 2>/dev/null)" ]; then
            info "Rules kept:   $DATA_DIR/rules.d/"
        fi

        # Remove the data dir itself only if nothing remains.
        if [ -z "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; then
            rmdir "$DATA_DIR"
            ok "Data directory removed"
        fi
    fi

    echo ""
    if [ "$_PLAIN" = "1" ]; then
        echo "Crust uninstalled successfully."
    else
        echo -e "${GREEN}${BOLD}Crust uninstalled successfully.${NC}"
    fi
    echo ""
}
