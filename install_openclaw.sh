#!/bin/bash
#
# Crust Installer for OpenClaw
# https://getcrust.io
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install_openclaw.sh | bash
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
    trap 'rm -f "$_common_tmp"' EXIT
    if command -v curl &>/dev/null; then
        curl -fsSL "https://raw.githubusercontent.com/BakeLens/crust/main/scripts/install-common.sh" -o "$_common_tmp"
    elif command -v wget &>/dev/null; then
        wget -q "https://raw.githubusercontent.com/BakeLens/crust/main/scripts/install-common.sh" -O "$_common_tmp"
    else
        echo "Error: curl or wget required" >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$_common_tmp"
fi

main() {
    parse_args "$@"

    if [ -n "$DO_UNINSTALL" ]; then
        run_uninstall
        exit 0
    fi

    print_banner ""

    # ── OpenClaw introduction ─────────────────────────────────────────────────
    echo -e "${BOLD}Why Crust for OpenClaw?${NC}"
    echo ""
    echo "  OpenClaw gives your agents real power — executing code, reading files,"
    echo "  making API calls. That's what makes it great. But it also means a single"
    echo "  hallucination or prompt injection could read .env files, leak SSH keys,"
    echo "  or run rm -rf on a user's project."
    echo ""
    echo "  Crust is a lightweight security gateway that sits between your agents"
    echo "  and LLM providers. It inspects every tool call and blocks dangerous ones"
    echo "  before they execute — so your users get all the power without the risk."
    echo ""
    echo "  It runs 100% locally. Your users' data never leaves their machine."
    echo ""

    init_steps 7

    step "Detecting system"
    detect_platform

    step "Checking requirements"
    check_requirements "go"

    step "Fetching version"
    resolve_version

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

    step "Cloning repository"
    clone_repo "$VERSION" "$tmp_dir/crust"

    step "Building Crust"
    build_go_binary "$tmp_dir/crust" "$VERSION"

    step "Installing"
    install_go_binary "$tmp_dir/crust"
    setup_data_dir

    step "Finalizing"
    setup_completion

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

    # ── Auto-start in replace-block mode ─────────────────────────────────────
    echo -e "${BOLD}Starting Crust in auto mode...${NC}"
    echo ""
    "$INSTALL_DIR/$BINARY_NAME" start --auto --block-mode replace
    echo ""

    # ── OpenClaw-specific setup instructions ─────────────────────────────────
    echo -e "${BOLD}Setup for OpenClaw${NC}"
    echo ""
    echo -e "  ${YELLOW}${BOLD}⚠  Important: Official Login vs API Key${NC}"
    echo ""
    echo -e "  If you're using ${BOLD}OpenAI or Anthropic's official login${NC} (OAuth/session-based):"
    echo -e "    ${RED}⚠  Crust is currently not compatible${NC}"
    echo ""
    echo "    OpenClaw hardcodes the official provider URLs (api.openai.com,"
    echo "    api.anthropic.com) and bypasses baseUrl configuration when using OAuth."
    echo ""
    echo "    Workaround: switch to API key authentication instead of OAuth login."
    echo "      • OpenAI:    https://platform.openai.com/api-keys"
    echo "      • Anthropic: https://console.anthropic.com/settings/keys"
    echo ""
    echo -e "  If you're using ${BOLD}third-party API providers${NC} or ${BOLD}API keys${NC}:"
    echo -e "    ${GREEN}✔  Follow the setup below${NC}"
    echo ""
    echo "  ──────────────────────────────────────────────────────────────────"
    echo ""
    echo "  Edit ~/.openclaw/openclaw.json to route traffic through Crust."
    echo ""
    echo -e "  ${YELLOW}Option A — Third-party API providers (OpenRouter, etc.)${NC}"
    echo ""
    echo "    Change the baseUrl in your provider config:"
    echo ""
    echo -e "    ${GREEN}\"models\": {"
    echo "      \"providers\": {"
    echo "        \"your-provider\": {"
    echo -e "          \"baseUrl\": \"http://localhost:9090\",  ${BLUE}← change this${NC}"
    echo -e "    ${GREEN}          \"apiKey\":  \"...\","
    echo "          ..."
    echo "        }"
    echo "      }"
    echo -e "    }${NC}"
    echo ""
    echo -e "  ${YELLOW}Option B — Direct API keys (custom provider config)${NC}"
    echo ""
    echo "    Add a provider under models.providers:"
    echo ""
    echo -e "    ${GREEN}\"models\": {"
    echo "      \"mode\": \"merge\","
    echo "      \"providers\": {"
    echo "        \"crust\": {"
    echo "          \"baseUrl\": \"http://localhost:9090\","
    echo "          \"apiKey\":  \"sk-ant-...\","
    echo "          \"api\":     \"anthropic-messages\","
    echo "          \"models\":  [{ \"id\": \"claude-sonnet-4-5\", \"name\": \"Claude Sonnet 4.5\" }]"
    echo "        }"
    echo "      }"
    echo -e "    }${NC}"
    echo ""
    echo "    Then set your model to crust/claude-sonnet-4-5."
    echo ""
    echo "  Crust auto-routes to the right provider from the model name"
    echo "  and passes through your auth tokens — no extra config needed."
    echo ""
    echo "  After updating openclaw.json, restart the gateway:"
    echo ""
    echo -e "    ${GREEN}systemctl --user restart openclaw-gateway${NC}"
    echo ""
    echo -e "${BOLD}Commands${NC}"
    echo ""
    echo "    crust status     # Check status"
    echo "    crust logs -f    # Follow logs"
    echo "    crust stop       # Stop crust"
    echo ""
}

main "$@"
