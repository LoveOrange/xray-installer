#!/bin/bash

#===============================================================================
# Xray Auto Installation Script
# Author: Your Name
# Repository: https://github.com/yourusername/xray-installer
# 
# Features:
#   - Install essential packages (git, zsh, wget, vim, etc.)
#   - Create 'xray' user with sudo privileges
#   - Setup password with double confirmation
#   - Nginx reverse proxy with camouflage website
#   - acme.sh for SSL certificate management
#   - Xray with VLESS + XTLS-Vision or REALITY
#   - BBR congestion control
#   - Optional: Secondary IP for specific sites
#
# Usage: bash install.sh
#===============================================================================

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load library functions
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/lib/colors.sh"

#===============================================================================
# Configuration Variables (will be set interactively or via config file)
#===============================================================================
CONFIG_FILE="${SCRIPT_DIR}/config.env"

# Default values
XRAY_USER="xray"
XRAY_HOME=""  # Will be set based on user
CERTS_DIR=""  # ~/certs
XRAY_DIR=""   # ~/xray
WEB_DIR=""    # ~/web
LOG_DIR=""    # ~/xray/logs

# Domain and certificate settings
DOMAIN=""
EMAIL=""

# Security mode: "tls" or "reality"
SECURITY_MODE="tls"

# REALITY settings
REALITY_DEST="www.microsoft.com:443"
REALITY_SERVER_NAMES="www.microsoft.com,microsoft.com"

# Camouflage settings
CAMOUFLAGE_SITE="hackernews"  # hackernews, custom, or URL

# Secondary IP settings
USE_SECONDARY_IP="no"
SECONDARY_IP=""
SECONDARY_PORT=""
SECONDARY_USER=""
SECONDARY_PASS=""

#===============================================================================
# Interactive Setup
#===============================================================================
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
 __  __                   ___           _        _ _           
 \ \/ /_ __ __ _ _   _   |_ _|_ __  ___| |_ __ _| | | ___ _ __ 
  \  /| '__/ _` | | | |   | || '_ \/ __| __/ _` | | |/ _ \ '__|
  /  \| | | (_| | |_| |   | || | | \__ \ || (_| | | |  __/ |   
 /_/\_\_|  \__,_|\__, |  |___|_| |_|___/\__\__,_|_|_|\___|_|   
                 |___/                                         
EOF
    echo -e "${NC}"
    echo -e "${GREEN}Xray Auto Installation Script${NC}"
    echo -e "${YELLOW}Based on official XTLS documentation${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warn "Running as root. Will create a dedicated 'xray' user for security."
    fi
}

check_os() {
    # Detect OS and set up package manager
    if ! detect_os; then
        log_error "Failed to detect operating system."
        log_info "Supported: Debian, Ubuntu, CentOS, RHEL, Fedora, Rocky Linux, AlmaLinux, Arch, Manjaro"
        exit 1
    fi

    log_success "Operating system check passed."
}

check_dns_record() {
    local domain=$1
    
    log_info "Checking DNS record for ${domain}..."
    
    # Get server's public IP
    local server_ip=$(curl -s -4 --max-time 10 ifconfig.me 2>/dev/null || \
                      curl -s -4 --max-time 10 ipinfo.io/ip 2>/dev/null || \
                      curl -s -4 --max-time 10 icanhazip.com 2>/dev/null)
    
    if [[ -z "$server_ip" ]]; then
        log_warn "Could not detect server's public IP. Skipping DNS check."
        return 0
    fi
    
    log_info "Server IP: ${server_ip}"
    
    # Resolve domain to IP
    local domain_ip=$(dig +short "$domain" A 2>/dev/null | head -n1)
    
    if [[ -z "$domain_ip" ]]; then
        # Try with host command as fallback
        domain_ip=$(host "$domain" 2>/dev/null | grep "has address" | head -n1 | awk '{print $NF}')
    fi
    
    if [[ -z "$domain_ip" ]]; then
        echo ""
        log_error "DNS lookup failed for ${domain}"
        echo ""
        echo -e "${YELLOW}Possible reasons:${NC}"
        echo "  1. Domain does not exist"
        echo "  2. DNS record not configured"
        echo "  3. DNS propagation in progress (wait 5-10 minutes)"
        echo ""
        echo -e "${CYAN}To fix:${NC}"
        echo "  1. Go to your domain registrar / DNS provider"
        echo "  2. Add an A record:"
        echo "     - Name: $(echo $domain | cut -d. -f1)"
        echo "     - Type: A"
        echo "     - Value: ${server_ip}"
        echo "  3. Wait for DNS propagation (usually 5-10 minutes)"
        echo ""
        read -p "Continue anyway? [y/N]: " continue_anyway
        if [[ "${continue_anyway,,}" != "y" ]]; then
            exit 1
        fi
        return 1
    fi
    
    log_info "Domain ${domain} resolves to: ${domain_ip}"
    
    # Compare IPs
    if [[ "$server_ip" != "$domain_ip" ]]; then
        echo ""
        log_error "DNS record mismatch!"
        echo ""
        echo -e "${YELLOW}Current status:${NC}"
        echo "  Server IP:     ${server_ip}"
        echo "  Domain points: ${domain_ip}"
        echo ""
        echo -e "${CYAN}This will cause certificate issuance to fail!${NC}"
        echo ""
        echo "To fix:"
        echo "  1. Update your DNS A record to point to: ${server_ip}"
        echo "  2. Wait for DNS propagation (5-10 minutes)"
        echo "  3. Run this script again"
        echo ""
        read -p "Continue anyway? [y/N]: " continue_anyway
        if [[ "${continue_anyway,,}" != "y" ]]; then
            exit 1
        fi
        return 1
    fi
    
    log_success "DNS record is correct! ${domain} → ${server_ip}"
    return 0
}

interactive_setup() {
    show_banner
    check_root
    check_os
    
    echo -e "${CYAN}=== Step 1: User Configuration ===${NC}"
    echo ""
    
    # Username
    read -p "Enter username for Xray service [${XRAY_USER}]: " input
    XRAY_USER="${input:-$XRAY_USER}"
    
    # Check if user exists
    if id "$XRAY_USER" &>/dev/null; then
        log_info "User '$XRAY_USER' already exists."
        read -p "Do you want to use this existing user? [Y/n]: " use_existing
        if [[ "${use_existing,,}" == "n" ]]; then
            log_error "Please choose a different username or delete the existing user."
            exit 1
        fi
    else
        log_info "User '$XRAY_USER' will be created."
    fi
    
    XRAY_HOME="/home/${XRAY_USER}"
    CERTS_DIR="${XRAY_HOME}/certs"
    XRAY_DIR="${XRAY_HOME}/xray"
    WEB_DIR="${XRAY_HOME}/web"
    LOG_DIR="${XRAY_DIR}/logs"
    
    echo ""
    echo -e "${CYAN}=== Step 2: Domain Configuration ===${NC}"
    echo ""
    
    while [[ -z "$DOMAIN" ]]; do
        read -p "Enter your domain name (e.g., sub.example.com): " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            log_error "Domain name is required!"
        fi
    done
    
    read -p "Enter your email for certificate notifications: " EMAIL
    if [[ -z "$EMAIL" ]]; then
        EMAIL="admin@${DOMAIN}"
        log_info "Using default email: ${EMAIL}"
    fi
    
    echo ""
    echo -e "${CYAN}=== Step 3: Security Mode ===${NC}"
    echo ""
    echo "Choose security mode:"
    echo "  1) TLS (Traditional - requires valid domain and certificate)"
    echo "  2) REALITY (No certificate needed - uses camouflage)"
    echo ""
    read -p "Select mode [1]: " mode_choice
    
    case "$mode_choice" in
        2)
            SECURITY_MODE="reality"
            echo ""
            log_info "REALITY mode selected."
            log_info "Note: Domain is used for identification only, DNS record not required."
            echo ""
            read -p "Enter REALITY destination (e.g., www.microsoft.com:443) [${REALITY_DEST}]: " input
            REALITY_DEST="${input:-$REALITY_DEST}"
            
            read -p "Enter server names (comma-separated) [${REALITY_SERVER_NAMES}]: " input
            REALITY_SERVER_NAMES="${input:-$REALITY_SERVER_NAMES}"
            ;;
        *)
            SECURITY_MODE="tls"
            log_info "TLS mode selected."
            echo ""
            # Check DNS record for TLS mode
            check_dns_record "$DOMAIN"
            ;;
    esac
    
    echo ""
    
    # TLS mode uses Hacker News as camouflage (simplified for automatic setup)
    # REALITY mode doesn't need camouflage (handled by dest setting)
    if [[ "$SECURITY_MODE" == "tls" ]]; then
        echo -e "${CYAN}=== Step 4: Camouflage Website ===${NC}"
        echo ""
        log_info "Camouflage site: Hacker News (news.ycombinator.com)"
        log_info "This provides cover when unauthorized users access your server."
        CAMOUFLAGE_SITE="hackernews"
        CAMOUFLAGE_URL="https://news.ycombinator.com"
    else
        # REALITY mode - no camouflage needed
        echo -e "${CYAN}=== Step 4: Camouflage Website ===${NC}"
        echo ""
        log_info "REALITY mode uses '${REALITY_DEST}' as fallback destination."
        log_info "No additional camouflage website needed."
        CAMOUFLAGE_SITE="none"
    fi
    
    echo ""
    echo -e "${CYAN}=== Step 5: Residential Proxy for AI Sites (Optional) ===${NC}"
    echo ""
    echo "Route AI sites (ChatGPT, Claude, etc.) through a residential proxy"
    echo "to avoid datacenter IP detection."
    echo ""
    read -p "Do you want to use a residential proxy for AI sites? [y/N]: " use_sec_ip
    
    if [[ "${use_sec_ip,,}" == "y" ]]; then
        USE_SECONDARY_IP="yes"
        echo ""
        echo "Enter your SOCKS5 proxy details:"
        read -p "  Proxy IP address: " SECONDARY_IP
        read -p "  Proxy port: " SECONDARY_PORT
        read -p "  Username: " SECONDARY_USER
        read -s -p "  Password: " SECONDARY_PASS
        echo ""
        
        # Validate port
        if ! [[ "$SECONDARY_PORT" =~ ^[0-9]+$ ]]; then
            log_error "Invalid port number"
            USE_SECONDARY_IP="no"
        fi
    fi
    
    echo ""
    echo -e "${CYAN}=== Configuration Summary ===${NC}"
    echo ""
    echo -e "  User:           ${GREEN}${XRAY_USER}${NC}"
    echo -e "  Home:           ${GREEN}${XRAY_HOME}${NC}"
    echo -e "  Domain:         ${GREEN}${DOMAIN}${NC}"
    echo -e "  Email:          ${GREEN}${EMAIL}${NC}"
    echo -e "  Security Mode:  ${GREEN}${SECURITY_MODE}${NC}"
    echo -e "  Camouflage:     ${GREEN}${CAMOUFLAGE_SITE}${NC}"
    echo -e "  Certs Dir:      ${GREEN}${CERTS_DIR}${NC}"
    echo -e "  Xray Dir:       ${GREEN}${XRAY_DIR}${NC}"
    echo -e "  Web Dir:        ${GREEN}${WEB_DIR}${NC}"
    echo -e "  Log Dir:        ${GREEN}${LOG_DIR}${NC}"
    if [[ "$USE_SECONDARY_IP" == "yes" ]]; then
        echo -e "  Residential Proxy: ${GREEN}${SECONDARY_IP}:${SECONDARY_PORT}${NC}"
        echo -e "  AI Sites Routed:   ${GREEN}ChatGPT, Claude, OpenAI${NC}"
    fi
    echo ""
    
    read -p "Proceed with installation? [Y/n]: " confirm
    if [[ "${confirm,,}" == "n" ]]; then
        log_info "Installation cancelled."
        exit 0
    fi
    
    # Save configuration
    save_config
}

save_config() {
    cat > "${CONFIG_FILE}" << EOF
# Xray Installer Configuration
# Generated: $(date)

XRAY_USER="${XRAY_USER}"
XRAY_HOME="${XRAY_HOME}"
CERTS_DIR="${CERTS_DIR}"
XRAY_DIR="${XRAY_DIR}"
WEB_DIR="${WEB_DIR}"
LOG_DIR="${LOG_DIR}"

DOMAIN="${DOMAIN}"
EMAIL="${EMAIL}"

SECURITY_MODE="${SECURITY_MODE}"
REALITY_DEST="${REALITY_DEST}"
REALITY_SERVER_NAMES="${REALITY_SERVER_NAMES}"

CAMOUFLAGE_SITE="${CAMOUFLAGE_SITE}"
CAMOUFLAGE_URL="${CAMOUFLAGE_URL:-}"

USE_SECONDARY_IP="${USE_SECONDARY_IP}"
SECONDARY_IP="${SECONDARY_IP:-}"
SECONDARY_PORT="${SECONDARY_PORT:-}"
SECONDARY_USER="${SECONDARY_USER:-}"
EOF

    log_info "Configuration saved to ${CONFIG_FILE}"
}

load_config() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        source "${CONFIG_FILE}"
        log_info "Configuration loaded from ${CONFIG_FILE}"
        return 0
    fi
    return 1
}

#===============================================================================
# Installation Steps
#===============================================================================

step_install_packages() {
    log_step "Installing essential packages..."

    # Update package cache
    update_packages

    # Install packages (package name mapping is handled automatically)
    install_packages \
        git \
        zsh \
        wget \
        curl \
        vim \
        nano \
        htop \
        unzip \
        tar \
        socat \
        cron \
        lsof \
        net-tools \
        dnsutils \
        bind9-host \
        ca-certificates \
        gnupg \
        sudo \
        nginx \
        jq \
        openssl

    log_success "Essential packages installed."
}

step_create_user() {
    log_step "Setting up user '${XRAY_USER}'..."
    
    local user_exists=false
    
    if id "$XRAY_USER" &>/dev/null; then
        user_exists=true
        log_info "User '${XRAY_USER}' already exists."
    else
        # Create user with home directory and bash shell
        useradd -m -s /bin/bash "$XRAY_USER"
        log_info "User '${XRAY_USER}' created."
    fi
    
    # Add user to sudo group
    usermod -aG sudo "$XRAY_USER"
    log_info "User '${XRAY_USER}' added to sudo group."
    
    # Ask if user wants to set password
    echo ""
    echo -e "${CYAN}Password Setup for '${XRAY_USER}':${NC}"
    echo ""
    echo "The '${XRAY_USER}' user is primarily a service account for running Xray."
    echo "A password is optional - you can always access it via: sudo su - ${XRAY_USER}"
    echo ""
    
    if [[ "$user_exists" == "true" ]]; then
        read -p "Do you want to change password for '${XRAY_USER}'? [y/N]: " set_passwd
    else
        read -p "Do you want to set a password for '${XRAY_USER}'? [y/N]: " set_passwd
    fi
    
    if [[ "${set_passwd,,}" == "y" ]]; then
        echo ""
        while true; do
            read -s -p "Enter password: " pass1
            echo ""
            read -s -p "Confirm password: " pass2
            echo ""
            
            if [[ "$pass1" == "$pass2" ]]; then
                if [[ -n "$pass1" ]]; then
                    echo "${XRAY_USER}:${pass1}" | chpasswd
                    log_success "Password set successfully."
                    break
                else
                    log_error "Password cannot be empty!"
                fi
            else
                log_error "Passwords do not match! Please try again."
            fi
        done
    else
        log_info "Skipping password setup (recommended for service accounts)."
        log_info "Access via: sudo su - ${XRAY_USER}"
    fi
    
    # Create required directories
    sudo -u "$XRAY_USER" mkdir -p "${CERTS_DIR}"
    sudo -u "$XRAY_USER" mkdir -p "${XRAY_DIR}"
    sudo -u "$XRAY_USER" mkdir -p "${LOG_DIR}"
    sudo -u "$XRAY_USER" mkdir -p "${WEB_DIR}"
    
    # Create log files
    sudo -u "$XRAY_USER" touch "${LOG_DIR}/access.log"
    sudo -u "$XRAY_USER" touch "${LOG_DIR}/error.log"
    chmod 666 "${LOG_DIR}"/*.log
    
    log_success "User directories created."
}

step_setup_bbr() {
    log_step "Configuring BBR congestion control..."
    
    # Check if BBR is already enabled
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        log_info "BBR is already enabled."
        return 0
    fi
    
    # Check kernel version
    KERNEL_VERSION=$(uname -r | cut -d. -f1)
    if [[ "$KERNEL_VERSION" -lt 4 ]]; then
        log_warn "Kernel version is too old for BBR. Consider upgrading."
        return 1
    fi
    
    # Enable BBR
    cat >> /etc/sysctl.conf << EOF

# BBR Congestion Control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    
    sysctl -p
    
    # Verify
    if lsmod | grep -q tcp_bbr || sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        log_success "BBR enabled successfully."
    else
        log_warn "BBR may not be active. A reboot might be required."
    fi
}

step_install_acme() {
    log_step "Installing acme.sh for user '${XRAY_USER}'..."
    
    # Install acme.sh as the xray user (NOT as root)
    # Based on: https://xtls.github.io/document/level-0/ch06-certificates.html
    sudo -u "$XRAY_USER" -H bash -c "
        cd ~
        curl -sS https://get.acme.sh | sh
        
        # Make acme.sh command available
        source ~/.bashrc
        
        # Enable auto-upgrade
        ~/.acme.sh/acme.sh --upgrade --auto-upgrade
        
        # Set Let's Encrypt as default CA (ZeroSSL requires extra registration)
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    "
    
    # Verify installation
    if [[ ! -f "${XRAY_HOME}/.acme.sh/acme.sh" ]]; then
        log_error "acme.sh installation failed!"
        exit 1
    fi
    
    log_success "acme.sh installed for user '${XRAY_USER}'."
}

step_request_certificate() {
    if [[ "$SECURITY_MODE" == "reality" ]]; then
        log_info "REALITY mode - skipping certificate request."
        return 0
    fi
    
    log_step "Requesting SSL certificate for ${DOMAIN}..."
    
    # Verify nginx is running on port 80
    if ! systemctl is-active --quiet nginx; then
        log_error "Nginx is not running! Cannot request certificate."
        exit 1
    fi
    
    # Verify acme.sh is installed
    if [[ ! -f "${XRAY_HOME}/.acme.sh/acme.sh" ]]; then
        log_error "acme.sh not found at ${XRAY_HOME}/.acme.sh/acme.sh"
        exit 1
    fi
    
    # Test if the ACME challenge location is accessible
    log_info "Testing HTTP access to ${DOMAIN}..."
    
    # Create a test file
    echo "test-$(date +%s)" > "${WEB_DIR}/.well-known/acme-challenge/test"
    chown "${XRAY_USER}:${XRAY_USER}" "${WEB_DIR}/.well-known/acme-challenge/test"
    
    sleep 1
    
    local http_test=$(curl -s -o /dev/null -w "%{http_code}" "http://${DOMAIN}/.well-known/acme-challenge/test" 2>/dev/null || echo "000")
    rm -f "${WEB_DIR}/.well-known/acme-challenge/test"
    
    if [[ "$http_test" == "200" ]]; then
        log_success "HTTP challenge location is accessible."
    else
        log_warn "Could not verify HTTP access (code: ${http_test})."
        echo ""
        echo -e "${YELLOW}If certificate issuance fails, check:${NC}"
        echo "  1. Cloud provider firewall allows port 80"
        echo "  2. DNS record points to this server: dig ${DOMAIN} +short"
        echo "  3. Nginx is running: systemctl status nginx"
        echo ""
        read -p "Press Enter to continue anyway..."
    fi
    
    # Step 1: Test with staging server first (avoid rate limits)
    # Based on: https://xtls.github.io/document/level-0/ch06-certificates.html
    log_info "Testing certificate issuance (staging server)..."
    
    sudo -u "$XRAY_USER" -H bash -c "
        ${XRAY_HOME}/.acme.sh/acme.sh --issue \
            --server letsencrypt_test \
            -d ${DOMAIN} \
            -w ${WEB_DIR} \
            --keylength ec-256
    "
    
    if [[ $? -ne 0 ]]; then
        echo ""
        log_error "Certificate test failed!"
        echo ""
        echo -e "${YELLOW}Troubleshooting:${NC}"
        echo "  1. Check DNS: dig ${DOMAIN} +short"
        echo "  2. Check nginx: curl -I http://${DOMAIN}/.well-known/acme-challenge/"
        echo "  3. Check firewall: Ensure port 80 is open"
        echo ""
        echo "Run with debug for more info:"
        echo "  sudo -u ${XRAY_USER} ${XRAY_HOME}/.acme.sh/acme.sh --issue --server letsencrypt_test -d ${DOMAIN} -w ${WEB_DIR} --keylength ec-256 --debug"
        echo ""
        exit 1
    fi
    
    log_success "Test certificate issued successfully!"
    
    # Step 2: Request real certificate
    log_info "Requesting real certificate from Let's Encrypt..."
    
    sudo -u "$XRAY_USER" -H bash -c "
        ${XRAY_HOME}/.acme.sh/acme.sh --issue \
            -d ${DOMAIN} \
            -w ${WEB_DIR} \
            --keylength ec-256 \
            --force
    "
    
    if [[ $? -ne 0 ]]; then
        log_error "Certificate issuance failed!"
        exit 1
    fi
    
    log_success "Certificate issued successfully!"
    
    # Step 3: Install certificate to our directory
    log_info "Installing certificate to ${CERTS_DIR}..."
    
    sudo -u "$XRAY_USER" -H bash -c "
        ${XRAY_HOME}/.acme.sh/acme.sh --install-cert -d ${DOMAIN} --ecc \
            --fullchain-file ${CERTS_DIR}/xray.crt \
            --key-file ${CERTS_DIR}/xray.key
    "
    
    # Set proper permissions (readable by xray service)
    chmod 644 "${CERTS_DIR}/xray.crt"
    chmod 644 "${CERTS_DIR}/xray.key"
    
    # Show certificate info
    log_info "Certificate details:"
    openssl x509 -in "${CERTS_DIR}/xray.crt" -noout -subject -dates
    
    log_success "SSL certificate installed to ${CERTS_DIR}"
    
    # Setup certificate auto-renewal
    setup_cert_renewal
}

setup_cert_renewal() {
    log_info "Setting up automatic certificate renewal..."
    
    # Create certificate renewal script
    # Based on: https://xtls.github.io/document/level-0/ch06-certificates.html
    cat > "${CERTS_DIR}/xray-cert-renew.sh" << EOF
#!/bin/bash
#===============================================================================
# Certificate Renewal Script
# Based on: https://xtls.github.io/document/level-0/ch06-certificates.html
# Created: $(date)
#===============================================================================

DOMAIN="${DOMAIN}"
XRAY_HOME="${XRAY_HOME}"
CERTS_DIR="${CERTS_DIR}"
WEB_DIR="${WEB_DIR}"

echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Starting certificate renewal for \${DOMAIN}..."

# Renew certificate using webroot mode
\${XRAY_HOME}/.acme.sh/acme.sh --renew -d "\${DOMAIN}" --ecc --force
echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Certificate renewed."

# Install certificate
\${XRAY_HOME}/.acme.sh/acme.sh --install-cert -d "\${DOMAIN}" --ecc \\
    --fullchain-file "\${CERTS_DIR}/xray.crt" \\
    --key-file "\${CERTS_DIR}/xray.key"
echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Certificate installed."

# Set permissions
chmod 644 "\${CERTS_DIR}/xray.crt"
chmod 644 "\${CERTS_DIR}/xray.key"
echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Permissions updated."

# Restart Xray to load new certificate
sudo systemctl restart xray
echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Xray restarted."

echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Certificate renewal completed!"

# Show new certificate info
openssl x509 -in "\${CERTS_DIR}/xray.crt" -noout -dates
EOF
    
    # Make script executable and set ownership
    chmod +x "${CERTS_DIR}/xray-cert-renew.sh"
    chown "${XRAY_USER}:${XRAY_USER}" "${CERTS_DIR}/xray-cert-renew.sh"
    
    # Add crontab entry for monthly renewal (1st day of month at 1:00 AM)
    local cron_cmd="0 1 1 * * bash ${CERTS_DIR}/xray-cert-renew.sh >> ${CERTS_DIR}/renewal.log 2>&1"
    
    # Add to user's crontab if not already present
    if ! sudo -u "$XRAY_USER" crontab -l 2>/dev/null | grep -q "xray-cert-renew.sh"; then
        (sudo -u "$XRAY_USER" crontab -l 2>/dev/null; echo "$cron_cmd") | sudo -u "$XRAY_USER" crontab -
        log_info "Crontab entry added: Monthly certificate renewal on the 1st at 1:00 AM"
    else
        log_info "Crontab entry already exists"
    fi
    
    log_success "Certificate auto-renewal configured."
}

step_setup_nginx() {
    log_step "Setting up Nginx on port 80..."

    # Backup original config
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak

    # Change nginx user to xray user
    sed -i "s/^user .*/user ${XRAY_USER};/" /etc/nginx/nginx.conf

    # Create webroot directory for ACME challenge
    mkdir -p "${WEB_DIR}/.well-known/acme-challenge"
    chown -R "${XRAY_USER}:${XRAY_USER}" "${WEB_DIR}"

    # Determine nginx config paths based on OS
    local NGINX_CONFIG_FILE
    local NGINX_SYMLINK_NEEDED=false

    case "$OS" in
        ubuntu|debian)
            NGINX_CONFIG_FILE="/etc/nginx/sites-available/xray"
            NGINX_SYMLINK_NEEDED=true
            ;;
        centos|rhel|fedora|rocky|almalinux|arch|manjaro)
            NGINX_CONFIG_FILE="/etc/nginx/conf.d/xray.conf"
            # Remove default.conf if it exists
            rm -f /etc/nginx/conf.d/default.conf
            ;;
        *)
            NGINX_CONFIG_FILE="/etc/nginx/conf.d/xray.conf"
            ;;
    esac

    log_info "Using nginx config: ${NGINX_CONFIG_FILE}"

    # REALITY mode: minimal nginx (just HTTP redirect)
    if [[ "$SECURITY_MODE" == "reality" ]]; then
        log_info "REALITY mode: Setting up minimal Nginx..."

        cat > "${NGINX_CONFIG_FILE}" << EOF
# HTTP redirect only (REALITY mode)
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://\$host\$request_uri;
}
EOF
    else
        # TLS mode: Setup HTTP server for ACME verification + Hacker News reverse proxy
        # This will be updated later to add HTTPS fallback after certificate is obtained
        log_info "TLS mode: Setting up HTTP server for certificate verification..."

        cat > "${NGINX_CONFIG_FILE}" << EOF
# HTTP server on port 80
# Purpose: 
#   1. ACME challenge for certificate issuance/renewal
#   2. Camouflage site (reverse proxy to Hacker News)
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    
    # ACME challenge location (required for certificate verification)
    location /.well-known/acme-challenge/ {
        root ${WEB_DIR};
        allow all;
    }
    
    # Reverse proxy to Hacker News (camouflage)
    location / {
        proxy_pass https://news.ycombinator.com;
        proxy_set_header Host news.ycombinator.com;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_ssl_server_name on;
        
        # Handle redirects
        proxy_redirect https://news.ycombinator.com/ /;
    }
}
EOF
    fi

    # Enable the site (Debian/Ubuntu only)
    if [[ "$NGINX_SYMLINK_NEEDED" == "true" ]]; then
        rm -f /etc/nginx/sites-enabled/default
        ln -sf /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/xray
        log_info "Symlink created for nginx site configuration."
    fi

    # Test nginx configuration
    if ! nginx -t; then
        log_error "Nginx configuration test failed!"
        exit 1
    fi
    
    # Start nginx
    systemctl enable nginx
    systemctl restart nginx
    
    # Verify nginx is running
    if ! systemctl is-active --quiet nginx; then
        log_error "Failed to start nginx!"
        journalctl -u nginx -n 10
        exit 1
    fi
    
    log_success "Nginx configured and running on port 80."
    log_info "Camouflage site: Hacker News (news.ycombinator.com)"
}

# Update nginx config after certificate is obtained (TLS mode only)
step_update_nginx_ssl() {
    if [[ "$SECURITY_MODE" == "reality" ]]; then
        log_info "REALITY mode - skipping nginx SSL update."
        return 0
    fi

    log_step "Updating Nginx with SSL fallback configuration..."

    # Determine nginx config path based on OS
    local NGINX_CONFIG_FILE
    case "$OS" in
        ubuntu|debian)
            NGINX_CONFIG_FILE="/etc/nginx/sites-available/xray"
            ;;
        centos|rhel|fedora|rocky|almalinux|arch|manjaro)
            NGINX_CONFIG_FILE="/etc/nginx/conf.d/xray.conf"
            ;;
        *)
            NGINX_CONFIG_FILE="/etc/nginx/conf.d/xray.conf"
            ;;
    esac

    # Now add the SSL fallback server block for Xray
    cat > "${NGINX_CONFIG_FILE}" << EOF
# HTTP server on port 80
# Purpose: ACME challenge + redirect to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    
    # ACME challenge location (required for certificate renewal)
    location /.well-known/acme-challenge/ {
        root ${WEB_DIR};
        allow all;
    }
    
    # Redirect all other requests to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

# HTTPS fallback server (receives traffic from Xray on failed auth)
# Xray listens on 443, falls back to 127.0.0.1:8080 for unauthorized requests
server {
    listen 127.0.0.1:8080;
    server_name ${DOMAIN};
    
    # Reverse proxy to Hacker News (camouflage)
    location / {
        proxy_pass https://news.ycombinator.com;
        proxy_set_header Host news.ycombinator.com;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_ssl_server_name on;
        
        # Handle redirects
        proxy_redirect https://news.ycombinator.com/ /;
        
        # Optimize
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
}
EOF
    
    # Test nginx configuration
    if ! nginx -t; then
        log_error "Nginx configuration test failed!"
        exit 1
    fi
    
    # Reload nginx
    systemctl reload nginx
    
    log_success "Nginx updated with SSL fallback configuration."
}

step_install_xray() {
    log_step "Installing Xray..."
    
    # Use official installation script with custom user
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u "${XRAY_USER}"
    
    log_success "Xray installed."
}

step_configure_xray() {
    log_step "Configuring Xray..."
    
    # Generate UUID
    UUID=$(xray uuid)
    log_info "Generated UUID: ${UUID}"
    
    if [[ "$SECURITY_MODE" == "reality" ]]; then
        # Generate REALITY keys
        KEYS=$(xray x25519)
        PRIVATE_KEY=$(echo "$KEYS" | grep "Private" | awk '{print $3}')
        PUBLIC_KEY=$(echo "$KEYS" | grep "Public" | awk '{print $3}')
        SHORT_ID=$(openssl rand -hex 8)
        
        log_info "REALITY Private Key: ${PRIVATE_KEY}"
        log_info "REALITY Public Key: ${PUBLIC_KEY}"
        log_info "Short ID: ${SHORT_ID}"
        
        # Build server names JSON array
        SERVER_NAMES_JSON=$(echo "${REALITY_SERVER_NAMES}" | sed 's/,/","/g' | sed 's/^/["/;s/$/"]/')
        
        # Build routing rules based on whether residential proxy is configured
        if [[ "$USE_SECONDARY_IP" == "yes" ]]; then
            ROUTING_RULES='"rules": [
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "ip": ["geoip:cn"],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "domain": ["geosite:category-ads-all"],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "network": "udp",
                "domain": [
                    "geosite:openai",
                    "geosite:anthropic",
                    "domain:anthropic.com",
                    "domain:claude.ai",
                    "domain:openai.com",
                    "domain:chatgpt.com",
                    "domain:chat.openai.com",
                    "domain:ai.com"
                ],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "network": "tcp",
                "domain": [
                    "geosite:openai",
                    "geosite:anthropic",
                    "domain:anthropic.com",
                    "domain:claude.ai",
                    "domain:openai.com",
                    "domain:chatgpt.com",
                    "domain:chat.openai.com",
                    "domain:ai.com"
                ],
                "outboundTag": "residential_proxy"
            }
        ]'
            DOMAIN_STRATEGY="AsIs"
            OUTBOUNDS='"outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom"
        },
        {
            "tag": "residential_proxy",
            "protocol": "socks",
            "settings": {
                "servers": [
                    {
                        "address": "'"${SECONDARY_IP}"'",
                        "port": '"${SECONDARY_PORT}"',
                        "users": [
                            {
                                "user": "'"${SECONDARY_USER}"'",
                                "pass": "'"${SECONDARY_PASS}"'"
                            }
                        ]
                    }
                ]
            }
        },
        {
            "tag": "block",
            "protocol": "blackhole"
        }
    ]'
        else
            # Simple routing without residential proxy
            ROUTING_RULES='"rules": [
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "ip": ["geoip:cn"],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "domain": ["geosite:category-ads-all"],
                "outboundTag": "block"
            }
        ]'
            DOMAIN_STRATEGY="IPIfNonMatch"
            OUTBOUNDS='"outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom"
        },
        {
            "tag": "block",
            "protocol": "blackhole"
        }
    ]'
        fi
        
        # Create REALITY configuration
        cat > /usr/local/etc/xray/config.json << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "${LOG_DIR}/access.log",
        "error": "${LOG_DIR}/error.log"
    },
    "routing": {
        "domainStrategy": "${DOMAIN_STRATEGY}",
        ${ROUTING_RULES}
    },
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${UUID}",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "${REALITY_DEST}",
                    "xver": 0,
                    "serverNames": ${SERVER_NAMES_JSON},
                    "privateKey": "${PRIVATE_KEY}",
                    "shortIds": ["${SHORT_ID}", ""]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        }
    ],
    ${OUTBOUNDS}
}
EOF
        
        # Save client configuration info
        SERVER_IP=$(curl -s -4 ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
        
        cat > "${XRAY_HOME}/client-config.txt" << EOF
================================================================================
                    XRAY CLIENT CONFIGURATION
                    Generated: $(date)
================================================================================

=== Server Information ===
Server IP:      ${SERVER_IP}
Port:           443
Protocol:       VLESS
Security:       REALITY
Network:        TCP

=== VLESS Settings ===
UUID:           ${UUID}
Flow:           xtls-rprx-vision
Encryption:     none

=== REALITY Settings ===
SNI:            $(echo "${REALITY_SERVER_NAMES}" | cut -d',' -f1)
Fingerprint:    chrome (recommended) / firefox / safari
Public Key:     ${PUBLIC_KEY}
Short ID:       ${SHORT_ID}

=== Share Links ===

--- v2rayN / v2rayNG / Nekoray ---
vless://${UUID}@${SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$(echo "${REALITY_SERVER_NAMES}" | cut -d',' -f1)&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp#Xray-REALITY

--- Clash Meta / Stash ---
- name: "Xray-REALITY"
  type: vless
  server: ${SERVER_IP}
  port: 443
  uuid: ${UUID}
  network: tcp
  udp: true
  tls: true
  flow: xtls-rprx-vision
  servername: $(echo "${REALITY_SERVER_NAMES}" | cut -d',' -f1)
  reality-opts:
    public-key: ${PUBLIC_KEY}
    short-id: ${SHORT_ID}
  client-fingerprint: chrome

--- Shadowrocket (iOS) ---
vless://${UUID}@${SERVER_IP}:443?encryption=none&security=reality&type=tcp&headerType=none&host=$(echo "${REALITY_SERVER_NAMES}" | cut -d',' -f1)&sni=$(echo "${REALITY_SERVER_NAMES}" | cut -d',' -f1)&fp=ios&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&flow=xtls-rprx-vision#Xray-REALITY

--- Quantumult X ---
vless=${SERVER_IP}:443, method=none, password=${UUID}, obfs=over-tls, obfs-host=$(echo "${REALITY_SERVER_NAMES}" | cut -d',' -f1), tls-verification=false, fast-open=false, udp-relay=false, tag=Xray-REALITY

================================================================================
                         IMPORTANT NOTES
================================================================================
1. Replace "chrome" with your preferred fingerprint if needed
2. This configuration uses REALITY - no domain/certificate needed
3. Keep your UUID and keys secure - they are your authentication

EOF
        if [[ "$USE_SECONDARY_IP" == "yes" ]]; then
            cat >> "${XRAY_HOME}/client-config.txt" << EOF
================================================================================
                    AI SITES ROUTING (Server-Side)
================================================================================
The following sites are routed through residential proxy on the server:
  ✓ claude.ai / anthropic.com
  ✓ chatgpt.com / openai.com / chat.openai.com
  ✓ ai.com

Residential Proxy: ${SECONDARY_IP}:${SECONDARY_PORT}

This is transparent to clients - just connect normally!
================================================================================
EOF
        fi
        
    else
        # TLS configuration
        if [[ "$USE_SECONDARY_IP" == "yes" ]]; then
            ROUTING_RULES='"rules": [
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "ip": ["geoip:cn"],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "domain": ["geosite:category-ads-all"],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "network": "udp",
                "domain": [
                    "geosite:openai",
                    "geosite:anthropic",
                    "domain:anthropic.com",
                    "domain:claude.ai",
                    "domain:openai.com",
                    "domain:chatgpt.com",
                    "domain:chat.openai.com",
                    "domain:ai.com"
                ],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "network": "tcp",
                "domain": [
                    "geosite:openai",
                    "geosite:anthropic",
                    "domain:anthropic.com",
                    "domain:claude.ai",
                    "domain:openai.com",
                    "domain:chatgpt.com",
                    "domain:chat.openai.com",
                    "domain:ai.com"
                ],
                "outboundTag": "residential_proxy"
            }
        ]'
            DOMAIN_STRATEGY="AsIs"
            OUTBOUNDS='"outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom"
        },
        {
            "tag": "residential_proxy",
            "protocol": "socks",
            "settings": {
                "servers": [
                    {
                        "address": "'"${SECONDARY_IP}"'",
                        "port": '"${SECONDARY_PORT}"',
                        "users": [
                            {
                                "user": "'"${SECONDARY_USER}"'",
                                "pass": "'"${SECONDARY_PASS}"'"
                            }
                        ]
                    }
                ]
            }
        },
        {
            "tag": "block",
            "protocol": "blackhole"
        }
    ]'
        else
            # Simple routing without residential proxy
            ROUTING_RULES='"rules": [
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "ip": ["geoip:cn"],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "domain": ["geosite:category-ads-all"],
                "outboundTag": "block"
            }
        ]'
            DOMAIN_STRATEGY="IPIfNonMatch"
            OUTBOUNDS='"outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom"
        },
        {
            "tag": "block",
            "protocol": "blackhole"
        }
    ]'
        fi
        
        # Create TLS configuration
        cat > /usr/local/etc/xray/config.json << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "${LOG_DIR}/access.log",
        "error": "${LOG_DIR}/error.log"
    },
    "dns": {
        "servers": [
            "https+local://1.1.1.1/dns-query",
            "localhost"
        ]
    },
    "routing": {
        "domainStrategy": "${DOMAIN_STRATEGY}",
        ${ROUTING_RULES}
    },
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${UUID}",
                        "flow": "xtls-rprx-vision",
                        "level": 0,
                        "email": "${EMAIL}"
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 8080
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["http/1.1"],
                    "certificates": [
                        {
                            "certificateFile": "${CERTS_DIR}/xray.crt",
                            "keyFile": "${CERTS_DIR}/xray.key"
                        }
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        }
    ],
    ${OUTBOUNDS}
}
EOF
        
        # Save client configuration info
        SERVER_IP=$(curl -s -4 ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
        
        cat > "${XRAY_HOME}/client-config.txt" << EOF
================================================================================
                    XRAY CLIENT CONFIGURATION
                    Generated: $(date)
================================================================================

=== Server Information ===
Domain:         ${DOMAIN}
Server IP:      ${SERVER_IP}
Port:           443
Protocol:       VLESS
Security:       TLS
Network:        TCP

=== VLESS Settings ===
UUID:           ${UUID}
Flow:           xtls-rprx-vision
Encryption:     none

=== TLS Settings ===
SNI:            ${DOMAIN}
ALPN:           http/1.1
Allow Insecure: false

=== Share Links ===

--- v2rayN / v2rayNG / Nekoray ---
vless://${UUID}@${DOMAIN}:443?encryption=none&flow=xtls-rprx-vision&security=tls&sni=${DOMAIN}&alpn=http%2F1.1&type=tcp#Xray-TLS

--- Clash Meta / Stash ---
- name: "Xray-TLS"
  type: vless
  server: ${DOMAIN}
  port: 443
  uuid: ${UUID}
  network: tcp
  udp: true
  tls: true
  flow: xtls-rprx-vision
  servername: ${DOMAIN}
  client-fingerprint: chrome

--- Shadowrocket (iOS) ---
vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&type=tcp&headerType=none&host=${DOMAIN}&sni=${DOMAIN}&flow=xtls-rprx-vision#Xray-TLS

--- Quantumult X ---
vless=${DOMAIN}:443, method=none, password=${UUID}, obfs=over-tls, obfs-host=${DOMAIN}, tls-verification=true, fast-open=false, udp-relay=false, tag=Xray-TLS

================================================================================
                         CERTIFICATE INFO
================================================================================
Certificate Location: ${CERTS_DIR}/xray.crt
Private Key Location: ${CERTS_DIR}/xray.key
Auto-Renewal Script:  ${CERTS_DIR}/xray-cert-renew.sh
Renewal Schedule:     1st of each month at 1:00 AM

To manually renew certificate:
  sudo -u ${XRAY_USER} bash ${CERTS_DIR}/xray-cert-renew.sh

To check certificate expiry:
  openssl x509 -in ${CERTS_DIR}/xray.crt -noout -dates

================================================================================
                         IMPORTANT NOTES
================================================================================
1. Use the domain name (${DOMAIN}) as server address, not IP
2. TLS certificate is valid for 90 days, auto-renewed monthly
3. Keep your UUID secure - it is your authentication

EOF
        if [[ "$USE_SECONDARY_IP" == "yes" ]]; then
            cat >> "${XRAY_HOME}/client-config.txt" << EOF
================================================================================
                    AI SITES ROUTING (Server-Side)
================================================================================
The following sites are routed through residential proxy on the server:
  ✓ claude.ai / anthropic.com
  ✓ chatgpt.com / openai.com / chat.openai.com
  ✓ ai.com

Residential Proxy: ${SECONDARY_IP}:${SECONDARY_PORT}

This is transparent to clients - just connect normally!
================================================================================
EOF
        fi
    fi
    
    chown "${XRAY_USER}:${XRAY_USER}" "${XRAY_HOME}/client-config.txt"
    
    log_success "Xray configured."
}

step_configure_xray_service() {
    log_step "Configuring Xray systemd service..."
    
    # The official install script creates /etc/systemd/system/xray.service
    # We need to modify it to use our user and fix permissions
    
    # Create override directory
    mkdir -p /etc/systemd/system/xray.service.d/
    
    # Create override file
    cat > /etc/systemd/system/xray.service.d/override.conf << EOF
[Service]
User=${XRAY_USER}
Group=${XRAY_USER}
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable and start Xray
    systemctl enable xray
    systemctl restart xray
    
    # Check status
    sleep 2
    if systemctl is-active --quiet xray; then
        log_success "Xray service started successfully."
    else
        log_error "Xray service failed to start. Check logs:"
        journalctl -u xray -n 20
        exit 1
    fi
}

step_setup_secondary_ip() {
    if [[ "$USE_SECONDARY_IP" != "yes" ]]; then
        return 0
    fi
    
    log_step "Setting up secondary IP routing..."
    
    # This is a placeholder for secondary IP configuration
    # Users would need to configure this based on their specific needs
    # (e.g., using warp, setting up a tunnel, etc.)
    
    log_warn "Secondary IP setup is complex and depends on your specific requirements."
    log_info "Please refer to the documentation for manual setup."
    log_info "Consider using Cloudflare WARP for this purpose."
}

step_create_management_scripts() {
    log_step "Creating management scripts..."
    
    # Certificate renewal script
    cat > "${XRAY_HOME}/renew-cert.sh" << 'EOF'
#!/bin/bash
# Certificate renewal script

XRAY_HOME="$(dirname "$(readlink -f "$0")")"
source "${XRAY_HOME}/../xray-installer/config.env" 2>/dev/null || true

# Renew certificate
~/.acme.sh/acme.sh --renew -d ${DOMAIN} --ecc --force

# Install certificate
~/.acme.sh/acme.sh --install-cert -d ${DOMAIN} --ecc \
    --fullchain-file ${CERTS_DIR}/xray.crt \
    --key-file ${CERTS_DIR}/xray.key

# Restart Xray
sudo systemctl restart xray

echo "Certificate renewed and Xray restarted."
EOF
    
    # Status check script
    cat > "${XRAY_HOME}/status.sh" << 'EOF'
#!/bin/bash
# Status check script

echo "=== Xray Status ==="
systemctl status xray --no-pager

echo ""
echo "=== Nginx Status ==="
systemctl status nginx --no-pager

echo ""
echo "=== Port 443 Status ==="
ss -tlnp | grep :443

echo ""
echo "=== Recent Xray Logs ==="
tail -n 20 ~/xray/logs/error.log
EOF
    
    # Make scripts executable
    chmod +x "${XRAY_HOME}/renew-cert.sh"
    chmod +x "${XRAY_HOME}/status.sh"
    chown -R "${XRAY_USER}:${XRAY_USER}" "${XRAY_HOME}"
    
    log_success "Management scripts created."
}

show_completion() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          Installation Completed Successfully!              ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}=== Server Summary ===${NC}"
    echo -e "  User:           ${YELLOW}${XRAY_USER}${NC}"
    echo -e "  Security Mode:  ${YELLOW}${SECURITY_MODE^^}${NC}"
    if [[ "$SECURITY_MODE" == "tls" ]]; then
        echo -e "  Domain:         ${YELLOW}${DOMAIN}${NC}"
    else
        echo -e "  REALITY Dest:   ${YELLOW}${REALITY_DEST}${NC}"
    fi
    if [[ "$USE_SECONDARY_IP" == "yes" ]]; then
        echo -e "  AI Sites Proxy: ${YELLOW}${SECONDARY_IP}:${SECONDARY_PORT}${NC}"
    fi
    echo ""
    echo -e "${CYAN}=== Important Files ===${NC}"
    echo -e "  Client Config:  ${YELLOW}${XRAY_HOME}/client-config.txt${NC}"
    echo -e "  Xray Config:    ${YELLOW}/usr/local/etc/xray/config.json${NC}"
    echo -e "  Xray Logs:      ${YELLOW}${LOG_DIR}/${NC}"
    if [[ "$SECURITY_MODE" == "tls" ]]; then
        echo -e "  Certificates:   ${YELLOW}${CERTS_DIR}/${NC}"
        echo -e "  Cert Renewal:   ${YELLOW}${CERTS_DIR}/xray-cert-renew.sh${NC}"
    fi
    echo ""
    echo -e "${CYAN}=== Management Commands ===${NC}"
    echo -e "  Check status:   ${YELLOW}sudo systemctl status xray${NC}"
    echo -e "  Restart Xray:   ${YELLOW}sudo systemctl restart xray${NC}"
    echo -e "  View logs:      ${YELLOW}tail -f ${LOG_DIR}/error.log${NC}"
    echo -e "  View config:    ${YELLOW}cat ${XRAY_HOME}/client-config.txt${NC}"
    echo ""
    echo -e "${CYAN}=== Client Configuration ===${NC}"
    echo ""
    cat "${XRAY_HOME}/client-config.txt"
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Scan the QR code or copy the share link to your client!   ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
}

#===============================================================================
# Main Execution
#===============================================================================

main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root."
        echo "Please run: sudo bash $0"
        exit 1
    fi
    
    # Check for config file argument
    if [[ "$1" == "--config" && -f "$2" ]]; then
        CONFIG_FILE="$2"
        load_config
    elif [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "Usage: $0 [--config config.env]"
        echo ""
        echo "Options:"
        echo "  --config FILE    Load configuration from FILE"
        echo "  --help, -h       Show this help message"
        exit 0
    else
        interactive_setup
    fi
    
    # Execute installation steps
    step_install_packages
    step_create_user
    step_setup_bbr
    step_install_acme
    step_setup_nginx         # Setup nginx on port 80 FIRST
    step_request_certificate # Then request cert using webroot
    step_update_nginx_ssl    # Update nginx config for SSL
    step_install_xray
    step_configure_xray
    step_configure_xray_service
    step_setup_secondary_ip
    step_create_management_scripts
    
    show_completion
}

main "$@"