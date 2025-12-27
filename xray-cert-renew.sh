#!/bin/bash
#===============================================================================
# Certificate Renewal Script
# Based on: https://xtls.github.io/document/level-0/ch06-certificates.html
#
# This script is automatically created during installation and scheduled
# to run monthly via crontab.
#
# Manual usage: bash ~/xray_cert/xray-cert-renew.sh
#===============================================================================

# Configuration - these will be replaced during installation
DOMAIN="{{DOMAIN}}"
XRAY_USER="{{XRAY_USER}}"
XRAY_HOME="{{XRAY_HOME}}"
CERTS_DIR="{{CERTS_DIR}}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"; }

# Renew certificate using acme.sh
log_info "Starting certificate renewal for ${DOMAIN}..."

# Run acme.sh to renew
"${XRAY_HOME}/.acme.sh/acme.sh" --renew -d "${DOMAIN}" --ecc --force

if [[ $? -ne 0 ]]; then
    log_error "Certificate renewal failed!"
    exit 1
fi

log_info "Certificate renewed successfully."

# Install the renewed certificate
log_info "Installing renewed certificate..."

"${XRAY_HOME}/.acme.sh/acme.sh" --install-cert -d "${DOMAIN}" --ecc \
    --fullchain-file "${CERTS_DIR}/xray.crt" \
    --key-file "${CERTS_DIR}/xray.key"

if [[ $? -ne 0 ]]; then
    log_error "Certificate installation failed!"
    exit 1
fi

log_info "Certificate installed to ${CERTS_DIR}"

# Set proper permissions for the private key
chmod +r "${CERTS_DIR}/xray.key"
log_info "Read permission granted for private key."

# Restart Xray to load new certificate
sudo systemctl restart xray

if [[ $? -eq 0 ]]; then
    log_info "Xray restarted successfully."
else
    log_error "Failed to restart Xray!"
    exit 1
fi

log_info "Certificate renewal completed successfully!"

# Show certificate expiry info
echo ""
log_info "New certificate info:"
openssl x509 -in "${CERTS_DIR}/xray.crt" -noout -dates
