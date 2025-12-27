#!/bin/bash
#===============================================================================
# Xray Uninstaller
# Completely removes Xray and related configurations
#
# Usage: sudo bash uninstall.sh
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

# Configuration
XRAY_USER="${XRAY_USER:-xray}"
XRAY_HOME="/home/${XRAY_USER}"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

confirm_uninstall() {
    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                    WARNING: UNINSTALL                       ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "This will remove:"
    echo "  - Xray service and binary"
    echo "  - Xray configuration"
    echo "  - Nginx configuration (will restore default)"
    echo "  - acme.sh and certificates"
    echo "  - Log files"
    echo ""
    echo -e "${YELLOW}The user '${XRAY_USER}' will NOT be deleted.${NC}"
    echo ""
    
    read -p "Are you sure you want to continue? [y/N]: " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        log_info "Uninstall cancelled."
        exit 0
    fi
}

stop_services() {
    log_info "Stopping services..."
    
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    
    log_success "Services stopped."
}

remove_xray() {
    log_info "Removing Xray..."
    
    # Use official uninstall script if available
    if [[ -f /usr/local/bin/xray ]]; then
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge 2>/dev/null || {
            # Manual removal if script fails
            rm -f /usr/local/bin/xray
            rm -rf /usr/local/etc/xray
            rm -rf /usr/local/share/xray
            rm -rf /var/log/xray
            rm -f /etc/systemd/system/xray.service
            rm -f /etc/systemd/system/xray@.service
            rm -rf /etc/systemd/system/xray.service.d
        }
    fi
    
    systemctl daemon-reload
    
    log_success "Xray removed."
}

remove_acme() {
    log_info "Removing acme.sh..."
    
    if [[ -d "${XRAY_HOME}/.acme.sh" ]]; then
        sudo -u "$XRAY_USER" -H bash -c "~/.acme.sh/acme.sh --uninstall" 2>/dev/null || true
        rm -rf "${XRAY_HOME}/.acme.sh"
    fi
    
    log_success "acme.sh removed."
}

remove_certificates() {
    log_info "Removing certificates..."
    
    if [[ -d "${XRAY_HOME}/certs" ]]; then
        rm -rf "${XRAY_HOME}/certs"
    fi
    
    log_success "Certificates removed."
}

remove_logs() {
    log_info "Removing log files..."
    
    if [[ -d "${XRAY_HOME}/xray" ]]; then
        rm -rf "${XRAY_HOME}/xray"
    fi
    
    log_success "Log files removed."
}

remove_web() {
    log_info "Removing web files..."
    
    if [[ -d "${XRAY_HOME}/web" ]]; then
        rm -rf "${XRAY_HOME}/web"
    fi
    
    log_success "Web files removed."
}

restore_nginx() {
    log_info "Restoring Nginx configuration..."
    
    # Remove xray site config
    rm -f /etc/nginx/sites-enabled/xray
    rm -f /etc/nginx/sites-available/xray
    
    # Restore default site
    if [[ -f /etc/nginx/sites-available/default ]]; then
        ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
    fi
    
    # Restore nginx.conf backup if exists
    if [[ -f /etc/nginx/nginx.conf.bak ]]; then
        mv /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
    fi
    
    # Restart nginx
    systemctl restart nginx 2>/dev/null || true
    
    log_success "Nginx configuration restored."
}

remove_cron_jobs() {
    log_info "Removing cron jobs..."
    
    if id "$XRAY_USER" &>/dev/null; then
        sudo -u "$XRAY_USER" crontab -r 2>/dev/null || true
    fi
    
    log_success "Cron jobs removed."
}

remove_helper_scripts() {
    log_info "Removing helper scripts..."
    
    rm -f "${XRAY_HOME}/renew-cert.sh"
    rm -f "${XRAY_HOME}/status.sh"
    rm -f "${XRAY_HOME}/client-config.txt"
    rm -f "${XRAY_HOME}/cert-renewal.log"
    
    log_success "Helper scripts removed."
}

remove_config_file() {
    log_info "Removing installer configuration..."
    
    rm -f "${SCRIPT_DIR}/config.env"
    
    log_success "Configuration removed."
}

show_completion() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Uninstall Completed Successfully              ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "The following have been removed:"
    echo "  ✓ Xray service and binary"
    echo "  ✓ Xray configuration"
    echo "  ✓ SSL certificates"
    echo "  ✓ acme.sh"
    echo "  ✓ Log files"
    echo "  ✓ Cron jobs"
    echo ""
    echo -e "${YELLOW}Note: User '${XRAY_USER}' was NOT deleted.${NC}"
    echo "To delete the user, run: sudo userdel -r ${XRAY_USER}"
    echo ""
}

main() {
    check_root
    confirm_uninstall
    
    stop_services
    remove_xray
    remove_acme
    remove_certificates
    remove_logs
    remove_web
    restore_nginx
    remove_cron_jobs
    remove_helper_scripts
    remove_config_file
    
    show_completion
}

main "$@"
