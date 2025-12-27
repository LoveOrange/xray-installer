#!/bin/bash
#===============================================================================
# WARP Installation Helper
# Installs and configures Cloudflare WARP for secondary IP routing
#
# This allows routing specific sites (OpenAI, Netflix, etc.) through
# a different IP address.
#
# Usage: sudo bash warp.sh [install|configure|status|remove]
#===============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_CODENAME=$(lsb_release -cs 2>/dev/null || echo "")
    else
        log_error "Cannot detect OS"
        exit 1
    fi
}

install_warp() {
    log_info "Installing Cloudflare WARP..."
    
    detect_os
    
    # Add Cloudflare repository
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${OS_CODENAME} main" | tee /etc/apt/sources.list.d/cloudflare-client.list
    
    apt-get update
    apt-get install -y cloudflare-warp
    
    log_success "WARP installed."
    
    # Register
    log_info "Registering WARP..."
    warp-cli register
    
    # Set to proxy mode (doesn't take over all traffic)
    warp-cli set-mode proxy
    
    log_success "WARP registered and set to proxy mode."
}

configure_warp() {
    log_info "Configuring WARP for Xray..."
    
    # Connect WARP
    warp-cli connect
    
    sleep 2
    
    # Get WARP status
    log_info "WARP Status:"
    warp-cli status
    
    echo ""
    log_info "WARP Settings (save these for Xray config):"
    warp-cli settings
    
    echo ""
    echo -e "${CYAN}To use WARP with Xray, you need to extract the WireGuard configuration.${NC}"
    echo ""
    echo "The WARP proxy is available at: socks5://127.0.0.1:40000"
    echo ""
    echo "For direct WireGuard integration with Xray, you'll need:"
    echo "  - Private Key"
    echo "  - Public Key"
    echo "  - Reserved bytes"
    echo ""
    echo "These can be extracted from: /var/lib/cloudflare-warp/reg.json"
}

get_warp_config() {
    log_info "Extracting WARP configuration for Xray..."
    
    local reg_file="/var/lib/cloudflare-warp/reg.json"
    
    if [[ ! -f "$reg_file" ]]; then
        log_error "WARP registration file not found. Please run: $0 install first"
        exit 1
    fi
    
    echo ""
    echo -e "${CYAN}=== WARP Configuration for Xray ===${NC}"
    echo ""
    
    # Extract private key
    local private_key=$(jq -r '.secret_key // .private_key // empty' "$reg_file" 2>/dev/null)
    if [[ -n "$private_key" ]]; then
        echo -e "Private Key: ${GREEN}${private_key}${NC}"
    fi
    
    # Extract reserved bytes
    local reserved=$(jq -r '.config.reserved // [0,0,0] | @json' "$reg_file" 2>/dev/null)
    echo -e "Reserved: ${GREEN}${reserved}${NC}"
    
    # WARP endpoints
    echo ""
    echo "WARP Endpoints:"
    echo "  - engage.cloudflareclient.com:2408"
    echo "  - 162.159.193.1:2408"
    echo "  - [2606:4700:100::a29f:c001]:2408"
    
    # WARP public key (constant)
    echo ""
    echo -e "WARP Public Key: ${GREEN}bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=${NC}"
    
    echo ""
    echo -e "${YELLOW}Use these values in your Xray configuration's WireGuard outbound.${NC}"
}

status_warp() {
    log_info "WARP Status:"
    echo ""
    
    if command -v warp-cli &>/dev/null; then
        warp-cli status
        echo ""
        warp-cli settings
    else
        log_error "WARP is not installed"
        exit 1
    fi
}

remove_warp() {
    log_warn "Removing WARP..."
    
    warp-cli disconnect 2>/dev/null || true
    warp-cli delete 2>/dev/null || true
    
    apt-get remove -y cloudflare-warp
    apt-get autoremove -y
    
    rm -f /etc/apt/sources.list.d/cloudflare-client.list
    rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    
    log_success "WARP removed."
}

show_xray_config_example() {
    echo ""
    echo -e "${CYAN}=== Example Xray WireGuard Outbound ===${NC}"
    echo ""
    cat << 'EOF'
{
    "tag": "warp",
    "protocol": "wireguard",
    "settings": {
        "secretKey": "YOUR_WARP_PRIVATE_KEY",
        "address": [
            "172.16.0.2/32",
            "2606:4700:110:8a36:df92:102a:9602:fa18/128"
        ],
        "peers": [
            {
                "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "allowedIPs": ["0.0.0.0/0", "::/0"],
                "endpoint": "engage.cloudflareclient.com:2408"
            }
        ],
        "reserved": [0, 0, 0],
        "mtu": 1280
    }
}
EOF
    echo ""
    echo "Add routing rules to direct specific traffic through WARP:"
    echo ""
    cat << 'EOF'
{
    "type": "field",
    "domain": [
        "geosite:openai",
        "geosite:netflix",
        "domain:chat.openai.com",
        "domain:openai.com"
    ],
    "outboundTag": "warp"
}
EOF
}

show_help() {
    echo ""
    echo -e "${CYAN}WARP Installation Helper${NC}"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  install     Install and register Cloudflare WARP"
    echo "  configure   Configure WARP and show settings"
    echo "  config      Extract WARP config for Xray"
    echo "  status      Show WARP status"
    echo "  example     Show Xray configuration example"
    echo "  remove      Remove WARP"
    echo "  help        Show this help"
    echo ""
}

main() {
    local command=${1:-help}
    
    case "$command" in
        install)
            check_root
            install_warp
            configure_warp
            ;;
        configure)
            configure_warp
            ;;
        config)
            check_root
            get_warp_config
            ;;
        status)
            status_warp
            ;;
        example)
            show_xray_config_example
            ;;
        remove)
            check_root
            remove_warp
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: ${command}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
