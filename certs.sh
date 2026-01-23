#!/bin/bash
#===============================================================================
# Certificate Management Module
# Manages SSL certificates using acme.sh
#
# Usage: 
#   sudo bash certs.sh install              # Install acme.sh
#   sudo bash certs.sh issue <domain>       # Issue certificate
#   sudo bash certs.sh renew <domain>       # Renew certificate
#   sudo bash certs.sh revoke <domain>      # Revoke certificate
#   sudo bash certs.sh list                 # List certificates
#===============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load libraries
source "${SCRIPT_DIR}/lib/colors.sh" 2>/dev/null || {
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
}
source "${SCRIPT_DIR}/lib/utils.sh" 2>/dev/null || {
    log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
    log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
    log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
    log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
}

# Configuration
XRAY_USER="${XRAY_USER:-xray}"
XRAY_HOME="${XRAY_HOME:-/home/${XRAY_USER}}"
CERTS_DIR="${CERTS_DIR:-${XRAY_HOME}/certs}"
EMAIL="${EMAIL:-}"

#===============================================================================
# Functions
#===============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_user_exists() {
    if ! id "$XRAY_USER" &>/dev/null; then
        log_error "User '$XRAY_USER' does not exist"
        exit 1
    fi
}

install_acme() {
    log_info "Installing acme.sh for user ${XRAY_USER}..."

    check_user_exists

    # Create certs directory
    mkdir -p "${CERTS_DIR}"
    chown "${XRAY_USER}:${XRAY_USER}" "${CERTS_DIR}"

    # Detect OS and install dependencies
    detect_os || exit 1
    update_packages
    install_packages curl socat

    # Install acme.sh as the xray user
    local email_opt=""
    if [[ -n "$EMAIL" ]]; then
        email_opt="email=${EMAIL}"
    fi

    sudo -u "$XRAY_USER" -H bash -c "curl https://get.acme.sh | sh -s ${email_opt}"

    log_success "acme.sh installed successfully"
}

issue_certificate() {
    local domain=$1
    
    if [[ -z "$domain" ]]; then
        log_error "Domain name required"
        echo "Usage: $0 issue <domain>"
        exit 1
    fi
    
    log_info "Issuing certificate for ${domain}..."
    
    check_user_exists
    
    # Stop nginx/other services using port 80
    systemctl stop nginx 2>/dev/null || true
    
    # Issue certificate using standalone mode
    sudo -u "$XRAY_USER" -H bash -c "
        export HOME='${XRAY_HOME}'
        ~/.acme.sh/acme.sh --issue -d ${domain} --standalone --keylength ec-256
    "
    
    # Install certificate
    sudo -u "$XRAY_USER" -H bash -c "
        export HOME='${XRAY_HOME}'
        ~/.acme.sh/acme.sh --install-cert -d ${domain} --ecc \
            --fullchain-file ${CERTS_DIR}/xray.crt \
            --key-file ${CERTS_DIR}/xray.key \
            --reloadcmd 'sudo systemctl restart xray 2>/dev/null || true'
    "
    
    # Set permissions
    chmod 644 "${CERTS_DIR}/xray.crt"
    chmod 644 "${CERTS_DIR}/xray.key"
    
    # Restart nginx
    systemctl start nginx 2>/dev/null || true
    
    log_success "Certificate issued and installed to ${CERTS_DIR}"
}

issue_certificate_webroot() {
    local domain=$1
    local webroot=${2:-"${XRAY_HOME}/web"}
    
    if [[ -z "$domain" ]]; then
        log_error "Domain name required"
        echo "Usage: $0 issue-webroot <domain> [webroot]"
        exit 1
    fi
    
    log_info "Issuing certificate for ${domain} using webroot ${webroot}..."
    
    check_user_exists
    
    # Issue certificate using webroot mode
    sudo -u "$XRAY_USER" -H bash -c "
        export HOME='${XRAY_HOME}'
        ~/.acme.sh/acme.sh --issue -d ${domain} -w ${webroot} --keylength ec-256
    "
    
    # Install certificate
    sudo -u "$XRAY_USER" -H bash -c "
        export HOME='${XRAY_HOME}'
        ~/.acme.sh/acme.sh --install-cert -d ${domain} --ecc \
            --fullchain-file ${CERTS_DIR}/xray.crt \
            --key-file ${CERTS_DIR}/xray.key \
            --reloadcmd 'sudo systemctl restart xray 2>/dev/null || true'
    "
    
    # Set permissions
    chmod 644 "${CERTS_DIR}/xray.crt"
    chmod 644 "${CERTS_DIR}/xray.key"
    
    log_success "Certificate issued and installed to ${CERTS_DIR}"
}

renew_certificate() {
    local domain=$1
    
    log_info "Renewing certificate${domain:+ for ${domain}}..."
    
    check_user_exists
    
    if [[ -n "$domain" ]]; then
        sudo -u "$XRAY_USER" -H bash -c "
            export HOME='${XRAY_HOME}'
            ~/.acme.sh/acme.sh --renew -d ${domain} --ecc --force
        "
    else
        # Renew all certificates
        sudo -u "$XRAY_USER" -H bash -c "
            export HOME='${XRAY_HOME}'
            ~/.acme.sh/acme.sh --renew-all --force
        "
    fi
    
    log_success "Certificate(s) renewed"
}

revoke_certificate() {
    local domain=$1
    
    if [[ -z "$domain" ]]; then
        log_error "Domain name required"
        echo "Usage: $0 revoke <domain>"
        exit 1
    fi
    
    log_warn "This will revoke the certificate for ${domain}"
    read -p "Are you sure? [y/N]: " confirm
    
    if [[ "${confirm,,}" != "y" ]]; then
        log_info "Cancelled"
        exit 0
    fi
    
    sudo -u "$XRAY_USER" -H bash -c "
        export HOME='${XRAY_HOME}'
        ~/.acme.sh/acme.sh --revoke -d ${domain} --ecc
    "
    
    log_success "Certificate revoked"
}

list_certificates() {
    log_info "Listing certificates..."
    
    check_user_exists
    
    sudo -u "$XRAY_USER" -H bash -c "
        export HOME='${XRAY_HOME}'
        ~/.acme.sh/acme.sh --list
    "
    
    echo ""
    log_info "Installed certificates in ${CERTS_DIR}:"
    ls -la "${CERTS_DIR}" 2>/dev/null || echo "  (none)"
}

check_certificate() {
    local cert_file="${CERTS_DIR}/xray.crt"
    
    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate file not found: ${cert_file}"
        exit 1
    fi
    
    log_info "Certificate information:"
    echo ""
    
    openssl x509 -in "$cert_file" -noout -text | grep -A2 "Validity"
    echo ""
    openssl x509 -in "$cert_file" -noout -subject
    openssl x509 -in "$cert_file" -noout -issuer
    
    echo ""
    log_info "Expiration:"
    openssl x509 -in "$cert_file" -noout -enddate
}

setup_auto_renewal() {
    log_info "Setting up automatic certificate renewal..."
    
    check_user_exists
    
    # Create renewal script
    cat > "${XRAY_HOME}/renew-certs.sh" << 'EOF'
#!/bin/bash
export HOME="$(dirname "$(readlink -f "$0")")"
~/.acme.sh/acme.sh --renew-all
sudo systemctl restart xray 2>/dev/null || true
sudo systemctl restart nginx 2>/dev/null || true
EOF
    
    chown "${XRAY_USER}:${XRAY_USER}" "${XRAY_HOME}/renew-certs.sh"
    chmod +x "${XRAY_HOME}/renew-certs.sh"
    
    # Add crontab entry (runs at 2:30 AM on the 1st of each month)
    local cron_entry="30 2 1 * * ${XRAY_HOME}/renew-certs.sh >> ${XRAY_HOME}/cert-renewal.log 2>&1"
    
    # Check if entry already exists
    if sudo -u "$XRAY_USER" crontab -l 2>/dev/null | grep -q "renew-certs.sh"; then
        log_info "Cron entry already exists"
    else
        (sudo -u "$XRAY_USER" crontab -l 2>/dev/null; echo "$cron_entry") | sudo -u "$XRAY_USER" crontab -
        log_success "Cron job added for automatic renewal"
    fi
}

show_help() {
    echo ""
    echo -e "${CYAN}Certificate Management Script${NC}"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  install               Install acme.sh"
    echo "  issue <domain>        Issue certificate (standalone mode)"
    echo "  issue-webroot <domain> [webroot]  Issue certificate (webroot mode)"
    echo "  renew [domain]        Renew certificate(s)"
    echo "  revoke <domain>       Revoke certificate"
    echo "  list                  List all certificates"
    echo "  check                 Check certificate information"
    echo "  auto-renew            Setup automatic renewal cron job"
    echo "  help                  Show this help"
    echo ""
    echo "Environment Variables:"
    echo "  XRAY_USER   User account (default: xray)"
    echo "  XRAY_HOME   Home directory (default: /home/\$XRAY_USER)"
    echo "  CERTS_DIR   Certificates directory (default: \$XRAY_HOME/certs)"
    echo "  EMAIL       Email for certificate notifications"
    echo ""
}

#===============================================================================
# Main
#===============================================================================

main() {
    local command=${1:-help}
    shift || true
    
    case "$command" in
        install)
            check_root
            install_acme
            ;;
        issue)
            check_root
            issue_certificate "$@"
            ;;
        issue-webroot)
            check_root
            issue_certificate_webroot "$@"
            ;;
        renew)
            check_root
            renew_certificate "$@"
            ;;
        revoke)
            check_root
            revoke_certificate "$@"
            ;;
        list)
            list_certificates
            ;;
        check)
            check_certificate
            ;;
        auto-renew)
            check_root
            setup_auto_renewal
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
