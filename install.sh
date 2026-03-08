#!/bin/bash
#
# Crust Installer
# https://getcrust.io
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install.sh | bash
#
# With options:
#   curl -fsSL .../install.sh | bash -s -- --version v2.0.0
#   curl -fsSL .../install.sh | bash -s -- --no-tui
#
# Non-interactive (Docker/CI):
#   bash install.sh --local . --prefix /usr/local/bin --no-font --no-completion
#

set -e

# Source shared functions (works for both local and piped execution)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/scripts/install-common.sh" ]; then
    # shellcheck source=scripts/install-common.sh
    source "$SCRIPT_DIR/scripts/install-common.sh"
else
    # When piped via curl, download common script to temp
    _common_tmp=$(mktemp)
    if command -v curl &>/dev/null; then
        curl -fsSL "https://raw.githubusercontent.com/BakeLens/crust/main/scripts/install-common.sh" -o "$_common_tmp"
    elif command -v wget &>/dev/null; then
        wget -q "https://raw.githubusercontent.com/BakeLens/crust/main/scripts/install-common.sh" -O "$_common_tmp"
    elif command -v fetch &>/dev/null; then
        fetch -q -o "$_common_tmp" "https://raw.githubusercontent.com/BakeLens/crust/main/scripts/install-common.sh"
    else
        echo "Error: curl, wget, or fetch required" >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$_common_tmp"
fi

main() {
    parse_args "$@"

    if [ -n "$DO_UNINSTALL" ]; then
        # shellcheck disable=SC2119 # no extra paths to remove for basic uninstall
        run_uninstall
        exit 0
    fi

    print_banner ""

    local src_dir
    if [ -n "$LOCAL_SRC" ]; then
        init_steps 5
        src_dir="$LOCAL_SRC"
        if [ "$VERSION" = "latest" ]; then
            VERSION=$(git -C "$src_dir" describe --tags --always 2>/dev/null || echo "dev")
        fi
    else
        init_steps 7
    fi

    step "Detecting system"
    detect_platform

    step "Checking requirements"
    check_requirements "go"

    if [ -z "$LOCAL_SRC" ]; then
        step "Fetching version"
        resolve_version

        local tmp_dir
        tmp_dir=$(mktemp -d)
        trap 'rm -rf "$tmp_dir"; rm -f "${_common_tmp:-}"' EXIT

        step "Cloning repository"
        clone_repo "$VERSION" "$tmp_dir/crust"
        src_dir="$tmp_dir/crust"
    fi

    step "Building Crust"
    build_go_binary "$src_dir" "$VERSION"

    step "Installing"
    install_go_binary "$src_dir"
    setup_data_dir

    step "Finalizing"
    setup_completion
    setup_font

    echo ""
    if [ "${_PLAIN:-0}" = "1" ]; then
        echo "Crust installed successfully!"
    else
        echo -e "  ${GREEN}${BOLD}◆ Crust installed successfully!${NC}"
    fi
    echo ""
    echo -e "  ${BLUE}Binary${NC}  ${INSTALL_DIR}/${BINARY_NAME}"
    echo -e "  ${BLUE}Data${NC}    ${DATA_DIR}/"
    echo ""

    setup_path_hint

    echo -e "  ${BOLD}Quick Start${NC}"
    echo ""
    echo "    crust start      # Start with interactive setup"
    echo "    crust status     # Check status"
    echo "    crust logs -f    # Follow logs"
    echo "    crust stop       # Stop crust"
    echo ""
}

main "$@"
