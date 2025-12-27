#!/bin/bash

#===============================================================================
# XTLS/Xray Automated Installation Script
# 
# Features:
#   1. Create and configure xray user with secure password
#   2. Install Xray-core with XTLS support
#   3. Generate fake homepage for camouflage
#   4. Configure systemd service
#   5. Setup basic firewall rules
#   6. Generate UUID and keys automatically
#
# Usage: sudo bash install-xray.sh
#===============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
XRAY_USER="xray"
XRAY_HOME="/home/xray"
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_LOG_DIR="/var/log/xray"
WEB_ROOT="/var/www/html"
XRAY_PORT="${XRAY_PORT:-443}"
FALLBACK_PORT="${FALLBACK_PORT:-8080}"

#===============================================================================
# Helper Functions
#===============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
    
    log_info "Detected OS: $OS $VERSION"
    
    case $OS in
        ubuntu|debian)
            PKG_MANAGER="apt"
            PKG_UPDATE="apt update -y"
            PKG_INSTALL="apt install -y"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            PKG_MANAGER="yum"
            PKG_UPDATE="yum update -y"
            PKG_INSTALL="yum install -y"
            if command -v dnf &> /dev/null; then
                PKG_MANAGER="dnf"
                PKG_UPDATE="dnf update -y"
                PKG_INSTALL="dnf install -y"
            fi
            ;;
        arch|manjaro)
            PKG_MANAGER="pacman"
            PKG_UPDATE="pacman -Syu --noconfirm"
            PKG_INSTALL="pacman -S --noconfirm"
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

#===============================================================================
# 1. User Setup Functions
#===============================================================================

create_xray_user() {
    log_info "Creating xray user..."
    
    # Check if user already exists
    if id "$XRAY_USER" &>/dev/null; then
        log_warn "User '$XRAY_USER' already exists"
        read -p "Do you want to reset the password? (y/N): " reset_passwd
        if [[ "$reset_passwd" =~ ^[Yy]$ ]]; then
            set_user_password
        fi
    else
        # Create user with home directory
        useradd -m -s /bin/bash -d "$XRAY_HOME" "$XRAY_USER"
        log_success "User '$XRAY_USER' created"
        set_user_password
    fi
    
    # Create necessary directories
    mkdir -p "$XRAY_HOME"/{logs,configs}
    chown -R "$XRAY_USER:$XRAY_USER" "$XRAY_HOME"
    chmod 750 "$XRAY_HOME"
}

set_user_password() {
    log_info "Setting password for $XRAY_USER user..."
    
    while true; do
        read -sp "Enter password for $XRAY_USER: " password1
        echo
        read -sp "Confirm password: " password2
        echo
        
        if [[ "$password1" != "$password2" ]]; then
            log_error "Passwords do not match. Please try again."
            continue
        fi
        
        if [[ ${#password1} -lt 8 ]]; then
            log_error "Password must be at least 8 characters. Please try again."
            continue
        fi
        
        # Set the password
        echo "$XRAY_USER:$password1" | chpasswd
        log_success "Password set successfully for $XRAY_USER"
        break
    done
}

configure_sudoers() {
    log_info "Configuring sudo access for $XRAY_USER..."
    
    read -p "Add $XRAY_USER to sudoers? (y/N): " add_sudo
    
    if [[ "$add_sudo" =~ ^[Yy]$ ]]; then
        # Check if already in sudoers
        if grep -q "^$XRAY_USER" /etc/sudoers.d/* 2>/dev/null || \
           grep -q "^$XRAY_USER" /etc/sudoers 2>/dev/null; then
            log_warn "$XRAY_USER already has sudo privileges"
        else
            # Create sudoers file with limited permissions
            cat > /etc/sudoers.d/xray << EOF
# Xray user sudo configuration
# Limited sudo access for xray service management
$XRAY_USER ALL=(ALL) NOPASSWD: /bin/systemctl start xray
$XRAY_USER ALL=(ALL) NOPASSWD: /bin/systemctl stop xray
$XRAY_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart xray
$XRAY_USER ALL=(ALL) NOPASSWD: /bin/systemctl status xray
$XRAY_USER ALL=(ALL) NOPASSWD: /bin/systemctl reload xray
EOF
            chmod 440 /etc/sudoers.d/xray
            
            # Validate sudoers file
            if visudo -cf /etc/sudoers.d/xray; then
                log_success "Sudo privileges configured for $XRAY_USER (limited to xray service)"
            else
                log_error "Sudoers file validation failed, removing..."
                rm -f /etc/sudoers.d/xray
            fi
        fi
    else
        log_info "Skipping sudo configuration"
    fi
}

#===============================================================================
# 2. Fake Homepage Setup
#===============================================================================

install_web_server() {
    log_info "Installing nginx for fake homepage..."
    
    $PKG_UPDATE
    $PKG_INSTALL nginx
    
    systemctl enable nginx
    systemctl start nginx
    
    log_success "Nginx installed and started"
}

generate_fake_homepage() {
    log_info "Generating fake homepage for camouflage..."
    
    mkdir -p "$WEB_ROOT"
    
    # Generate random company name elements
    PREFIXES=("Tech" "Digital" "Cloud" "Smart" "Net" "Data" "Cyber" "Info" "Web" "Soft")
    SUFFIXES=("Solutions" "Systems" "Services" "Corp" "Labs" "Works" "Hub" "Pro" "Plus" "Group")
    
    RANDOM_PREFIX=${PREFIXES[$RANDOM % ${#PREFIXES[@]}]}
    RANDOM_SUFFIX=${SUFFIXES[$RANDOM % ${#SUFFIXES[@]}]}
    COMPANY_NAME="$RANDOM_PREFIX$RANDOM_SUFFIX"
    
    # Create fake homepage
    cat > "$WEB_ROOT/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>COMPANY_PLACEHOLDER - Enterprise Solutions</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .navbar {
            background: rgba(255,255,255,0.95);
            padding: 1rem 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            position: fixed;
            width: 100%;
            top: 0;
            z-index: 1000;
        }
        
        .navbar-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            font-size: 1.5rem;
            font-weight: 700;
            color: #667eea;
        }
        
        .nav-links {
            display: flex;
            gap: 2rem;
            list-style: none;
        }
        
        .nav-links a {
            text-decoration: none;
            color: #555;
            font-weight: 500;
            transition: color 0.3s;
        }
        
        .nav-links a:hover {
            color: #667eea;
        }
        
        .hero {
            padding: 10rem 2rem 6rem;
            text-align: center;
            color: white;
        }
        
        .hero h1 {
            font-size: 3rem;
            margin-bottom: 1.5rem;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .hero p {
            font-size: 1.25rem;
            max-width: 600px;
            margin: 0 auto 2rem;
            opacity: 0.9;
        }
        
        .btn {
            display: inline-block;
            padding: 1rem 2.5rem;
            background: white;
            color: #667eea;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 600;
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .features {
            background: white;
            padding: 5rem 2rem;
        }
        
        .features-grid {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
        }
        
        .feature-card {
            padding: 2rem;
            border-radius: 10px;
            background: #f8f9fa;
            text-align: center;
            transition: transform 0.3s;
        }
        
        .feature-card:hover {
            transform: translateY(-5px);
        }
        
        .feature-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        
        .feature-card h3 {
            margin-bottom: 1rem;
            color: #333;
        }
        
        .feature-card p {
            color: #666;
        }
        
        .footer {
            background: #1a1a2e;
            color: white;
            padding: 3rem 2rem;
            text-align: center;
        }
        
        .footer p {
            opacity: 0.7;
        }
        
        @media (max-width: 768px) {
            .nav-links {
                display: none;
            }
            
            .hero h1 {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-content">
            <div class="logo">COMPANY_PLACEHOLDER</div>
            <ul class="nav-links">
                <li><a href="#home">Home</a></li>
                <li><a href="#services">Services</a></li>
                <li><a href="#about">About</a></li>
                <li><a href="#contact">Contact</a></li>
            </ul>
        </div>
    </nav>

    <section class="hero" id="home">
        <h1>Enterprise Solutions for Modern Business</h1>
        <p>Empowering organizations with cutting-edge technology solutions that drive growth and innovation.</p>
        <a href="#contact" class="btn">Get Started</a>
    </section>

    <section class="features" id="services">
        <div class="features-grid">
            <div class="feature-card">
                <div class="feature-icon">☁️</div>
                <h3>Cloud Infrastructure</h3>
                <p>Scalable and secure cloud solutions designed for enterprise workloads.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🔒</div>
                <h3>Security Services</h3>
                <p>Comprehensive cybersecurity solutions to protect your digital assets.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">📊</div>
                <h3>Data Analytics</h3>
                <p>Transform your data into actionable insights with our analytics platform.</p>
            </div>
        </div>
    </section>

    <footer class="footer">
        <p>&copy; 2024 COMPANY_PLACEHOLDER. All rights reserved.</p>
        <p style="margin-top: 0.5rem; font-size: 0.875rem;">Building the future of enterprise technology.</p>
    </footer>

    <script>
        // Smooth scroll for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
    </script>
</body>
</html>
HTMLEOF

    # Replace placeholder with random company name
    sed -i "s/COMPANY_PLACEHOLDER/$COMPANY_NAME/g" "$WEB_ROOT/index.html"
    
    # Create additional fake pages for more authenticity
    mkdir -p "$WEB_ROOT"/{about,contact,services}
    
    # Create robots.txt
    cat > "$WEB_ROOT/robots.txt" << EOF
User-agent: *
Allow: /
Sitemap: https://example.com/sitemap.xml
EOF

    # Create a simple 404 page
    cat > "$WEB_ROOT/404.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>404 - Page Not Found</title>
    <style>
        body { font-family: sans-serif; text-align: center; padding: 50px; }
        h1 { color: #667eea; }
    </style>
</head>
<body>
    <h1>404</h1>
    <p>The page you're looking for doesn't exist.</p>
    <a href="/">Return Home</a>
</body>
</html>
EOF

    chown -R www-data:www-data "$WEB_ROOT" 2>/dev/null || \
    chown -R nginx:nginx "$WEB_ROOT" 2>/dev/null || true
    
    log_success "Fake homepage generated: $COMPANY_NAME"
}

configure_nginx_fallback() {
    log_info "Configuring nginx as fallback server..."
    
    # Backup original config
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup 2>/dev/null || true
    
    cat > /etc/nginx/conf.d/fallback.conf << EOF
server {
    listen 127.0.0.1:$FALLBACK_PORT;
    server_name _;
    
    root $WEB_ROOT;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    error_page 404 /404.html;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Hide nginx version
    server_tokens off;
    
    # Logging
    access_log /var/log/nginx/fallback_access.log;
    error_log /var/log/nginx/fallback_error.log;
}
EOF

    # Test and reload nginx
    nginx -t && systemctl reload nginx
    
    log_success "Nginx fallback configured on 127.0.0.1:$FALLBACK_PORT"
}

#===============================================================================
# 3. Xray Installation
#===============================================================================

install_dependencies() {
    log_info "Installing dependencies..."
    
    $PKG_UPDATE
    
    case $PKG_MANAGER in
        apt)
            $PKG_INSTALL curl wget unzip jq openssl ca-certificates
            ;;
        yum|dnf)
            $PKG_INSTALL curl wget unzip jq openssl ca-certificates
            ;;
        pacman)
            $PKG_INSTALL curl wget unzip jq openssl ca-certificates
            ;;
    esac
    
    log_success "Dependencies installed"
}

install_xray() {
    log_info "Installing Xray-core..."
    
    # Use official installation script
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    if command -v xray &> /dev/null; then
        XRAY_VERSION=$(xray version | head -n1)
        log_success "Xray installed: $XRAY_VERSION"
    else
        log_error "Xray installation failed"
        exit 1
    fi
}

generate_xray_config() {
    log_info "Generating Xray configuration..."
    
    mkdir -p "$XRAY_CONFIG_DIR"
    mkdir -p "$XRAY_LOG_DIR"
    
    # Generate UUID
    UUID=$(xray uuid)
    
    # Generate x25519 key pair for Reality
    KEY_PAIR=$(xray x25519)
    PRIVATE_KEY=$(echo "$KEY_PAIR" | grep "Private key:" | awk '{print $3}')
    PUBLIC_KEY=$(echo "$KEY_PAIR" | grep "Public key:" | awk '{print $3}')
    
    # Generate short ID
    SHORT_ID=$(openssl rand -hex 8)
    
    # Save credentials
    cat > "$XRAY_HOME/credentials.txt" << EOF
===========================================
XRAY CREDENTIALS - KEEP THIS SECURE!
===========================================
Generated: $(date)

UUID: $UUID
Private Key: $PRIVATE_KEY
Public Key: $PUBLIC_KEY
Short ID: $SHORT_ID
Port: $XRAY_PORT

Client Configuration:
---------------------
Address: YOUR_SERVER_IP
Port: $XRAY_PORT
UUID: $UUID
Flow: xtls-rprx-vision
Public Key: $PUBLIC_KEY
Short ID: $SHORT_ID
Server Name (SNI): www.microsoft.com
Fingerprint: chrome
===========================================
EOF
    
    chmod 600 "$XRAY_HOME/credentials.txt"
    chown "$XRAY_USER:$XRAY_USER" "$XRAY_HOME/credentials.txt"
    
    # Create Xray config with VLESS + XTLS-Reality
    cat > "$XRAY_CONFIG_DIR/config.json" << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "$XRAY_LOG_DIR/access.log",
        "error": "$XRAY_LOG_DIR/error.log"
    },
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "block"
            }
        ]
    },
    "inbounds": [
        {
            "tag": "vless-reality",
            "listen": "0.0.0.0",
            "port": $XRAY_PORT,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID",
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
                    "dest": "www.microsoft.com:443",
                    "xver": 0,
                    "serverNames": [
                        "www.microsoft.com",
                        "microsoft.com"
                    ],
                    "privateKey": "$PRIVATE_KEY",
                    "shortIds": [
                        "$SHORT_ID",
                        ""
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        }
    ],
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom"
        },
        {
            "tag": "block",
            "protocol": "blackhole"
        }
    ]
}
EOF

    chmod 644 "$XRAY_CONFIG_DIR/config.json"
    
    # Set log directory permissions
    chown -R "$XRAY_USER:$XRAY_USER" "$XRAY_LOG_DIR"
    
    log_success "Xray configuration generated"
    log_info "Credentials saved to: $XRAY_HOME/credentials.txt"
}

#===============================================================================
# 4. Systemd and Firewall
#===============================================================================

configure_systemd() {
    log_info "Configuring systemd service..."
    
    # The official installer creates this, but we'll customize it
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=$XRAY_USER
Group=$XRAY_USER
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config $XRAY_CONFIG_DIR/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable xray
    
    log_success "Systemd service configured"
}

configure_firewall() {
    log_info "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw allow $XRAY_PORT/tcp comment 'Xray XTLS'
        ufw allow 80/tcp comment 'HTTP'
        ufw allow 443/tcp comment 'HTTPS'
        log_success "UFW rules added"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=$XRAY_PORT/tcp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --reload
        log_success "Firewalld rules added"
    else
        log_warn "No firewall detected. Please configure manually."
        log_info "Required ports: $XRAY_PORT/tcp, 80/tcp, 443/tcp"
    fi
}

#===============================================================================
# 5. Final Steps
#===============================================================================

start_services() {
    log_info "Starting services..."
    
    systemctl restart nginx
    systemctl restart xray
    
    sleep 2
    
    if systemctl is-active --quiet xray; then
        log_success "Xray service is running"
    else
        log_error "Xray service failed to start"
        systemctl status xray --no-pager
        exit 1
    fi
    
    if systemctl is-active --quiet nginx; then
        log_success "Nginx service is running"
    else
        log_warn "Nginx service is not running"
    fi
}

print_summary() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}Installation Complete!${NC}"
    echo "=========================================="
    echo ""
    echo "Configuration Summary:"
    echo "----------------------"
    echo "Xray User: $XRAY_USER"
    echo "Xray Port: $XRAY_PORT"
    echo "Fallback Port: $FALLBACK_PORT"
    echo "Config File: $XRAY_CONFIG_DIR/config.json"
    echo "Credentials: $XRAY_HOME/credentials.txt"
    echo "Web Root: $WEB_ROOT"
    echo ""
    echo "Service Management:"
    echo "-------------------"
    echo "  systemctl start xray"
    echo "  systemctl stop xray"
    echo "  systemctl restart xray"
    echo "  systemctl status xray"
    echo ""
    echo "View Credentials:"
    echo "-----------------"
    echo "  cat $XRAY_HOME/credentials.txt"
    echo ""
    echo -e "${YELLOW}IMPORTANT: Save your credentials securely!${NC}"
    echo ""
}

#===============================================================================
# Main Execution
#===============================================================================

main() {
    clear
    echo "=========================================="
    echo "  XTLS/Xray Automated Installation"
    echo "=========================================="
    echo ""
    
    check_root
    check_os
    
    echo ""
    echo "This script will:"
    echo "  1. Create and configure xray user"
    echo "  2. Install Xray-core with XTLS Reality"
    echo "  3. Generate fake homepage for camouflage"
    echo "  4. Configure systemd and firewall"
    echo ""
    
    read -p "Continue with installation? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi
    
    echo ""
    
    # Step 1: User Setup
    log_info "=== Step 1: User Setup ==="
    create_xray_user
    configure_sudoers
    echo ""
    
    # Step 2: Install Dependencies
    log_info "=== Step 2: Installing Dependencies ==="
    install_dependencies
    echo ""
    
    # Step 3: Web Server and Fake Homepage
    log_info "=== Step 3: Web Server Setup ==="
    install_web_server
    generate_fake_homepage
    configure_nginx_fallback
    echo ""
    
    # Step 4: Xray Installation
    log_info "=== Step 4: Xray Installation ==="
    install_xray
    generate_xray_config
    echo ""
    
    # Step 5: Service Configuration
    log_info "=== Step 5: Service Configuration ==="
    configure_systemd
    configure_firewall
    echo ""
    
    # Step 6: Start Services
    log_info "=== Step 6: Starting Services ==="
    start_services
    echo ""
    
    # Print Summary
    print_summary
}

# Run main function
main "$@"
