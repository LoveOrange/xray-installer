#!/bin/bash
#===============================================================================
# Utility Functions Library
# Common functions used across all installation scripts
#===============================================================================

# Logging functions
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

log_step() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

#===============================================================================
# Multi-OS Support Functions
#===============================================================================

# OS detection variables (will be set by detect_os)
OS=""
OS_VERSION=""
PKG_MANAGER=""
PKG_UPDATE=""
PKG_INSTALL=""

# Detect operating system and set package manager
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS. /etc/os-release not found."
        return 1
    fi

    log_info "Detected OS: ${OS} ${OS_VERSION}"

    case $OS in
        ubuntu|debian)
            PKG_MANAGER="apt"
            PKG_UPDATE="apt-get update -y"
            PKG_INSTALL="apt-get install -y"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            PKG_MANAGER="yum"
            PKG_UPDATE="yum update -y"
            PKG_INSTALL="yum install -y"
            # Check if dnf is available (newer systems)
            if command_exists dnf; then
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
            log_info "Supported: Debian, Ubuntu, CentOS, RHEL, Fedora, Rocky Linux, AlmaLinux, Arch, Manjaro"
            return 1
            ;;
    esac

    log_success "Package manager: ${PKG_MANAGER}"
    return 0
}

# Update package manager cache
update_packages() {
    if [[ -z "$PKG_UPDATE" ]]; then
        detect_os || return 1
    fi

    log_info "Updating package manager cache..."
    eval "$PKG_UPDATE"
}

# Install packages (with OS-specific package name mapping)
install_packages() {
    if [[ -z "$PKG_INSTALL" ]]; then
        detect_os || return 1
    fi

    local packages=("$@")
    local mapped_packages=()

    # Map package names to OS-specific names
    for pkg in "${packages[@]}"; do
        case "$pkg" in
            # Handle packages with different names across distros
            "dnsutils")
                if [[ "$PKG_MANAGER" == "yum" || "$PKG_MANAGER" == "dnf" ]]; then
                    mapped_packages+=("bind-utils")
                elif [[ "$PKG_MANAGER" == "pacman" ]]; then
                    mapped_packages+=("bind")
                else
                    mapped_packages+=("$pkg")
                fi
                ;;
            "bind9-host")
                if [[ "$PKG_MANAGER" == "yum" || "$PKG_MANAGER" == "dnf" ]]; then
                    mapped_packages+=("bind-utils")
                elif [[ "$PKG_MANAGER" == "pacman" ]]; then
                    mapped_packages+=("bind")
                else
                    mapped_packages+=("$pkg")
                fi
                ;;
            "net-tools")
                mapped_packages+=("$pkg")
                ;;
            *)
                mapped_packages+=("$pkg")
                ;;
        esac
    done

    # Remove duplicates
    local unique_packages=($(printf "%s\n" "${mapped_packages[@]}" | sort -u))

    log_info "Installing packages: ${unique_packages[*]}"

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        export DEBIAN_FRONTEND=noninteractive
    fi

    eval "$PKG_INSTALL ${unique_packages[*]}"
}

# Check if a service is running
service_running() {
    systemctl is-active --quiet "$1"
}

# Check if port is in use
port_in_use() {
    local port=$1
    ss -tlnp | grep -q ":${port} "
}

# Wait for a service to be ready
wait_for_service() {
    local service=$1
    local max_attempts=${2:-30}
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if service_running "$service"; then
            return 0
        fi
        sleep 1
        ((attempt++))
    done
    
    return 1
}

# Validate domain name format
validate_domain() {
    local domain=$1
    if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

# Validate email format
validate_email() {
    local email=$1
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

# Validate IP address
validate_ip() {
    local ip=$1
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local IFS='.'
        read -ra octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ $octet -lt 0 || $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Get public IP address
get_public_ip() {
    local ip=""
    
    # Try multiple services
    for service in "ifconfig.me" "ipinfo.io/ip" "icanhazip.com" "api.ipify.org"; do
        ip=$(curl -s -m 5 "$service" 2>/dev/null)
        if validate_ip "$ip"; then
            echo "$ip"
            return 0
        fi
    done
    
    return 1
}

# Generate random string
generate_random_string() {
    local length=${1:-16}
    openssl rand -hex "$((length/2))"
}

# Generate UUID
generate_uuid() {
    if command_exists xray; then
        xray uuid
    elif command_exists uuidgen; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# Backup file with timestamp
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        local timestamp=$(date +%Y%m%d_%H%M%S)
        cp "$file" "${file}.backup.${timestamp}"
        log_info "Backed up $file"
    fi
}

# Check system resources
check_resources() {
    local min_ram=${1:-512}  # MB
    local min_disk=${2:-1}   # GB
    
    # Check RAM
    local ram_mb=$(free -m | awk '/^Mem:/{print $2}')
    if [[ $ram_mb -lt $min_ram ]]; then
        log_warn "Low RAM: ${ram_mb}MB (recommended: ${min_ram}MB+)"
    fi
    
    # Check disk space
    local disk_gb=$(df -BG / | awk 'NR==2{print $4}' | tr -d 'G')
    if [[ $disk_gb -lt $min_disk ]]; then
        log_warn "Low disk space: ${disk_gb}GB (recommended: ${min_disk}GB+)"
    fi
}

# Install package if not present
ensure_package() {
    local package=$1

    if [[ -z "$PKG_MANAGER" ]]; then
        detect_os || return 1
    fi

    # Check if package is already installed based on package manager
    case "$PKG_MANAGER" in
        apt)
            if ! dpkg -l "$package" 2>/dev/null | grep -q "^ii"; then
                install_packages "$package"
            fi
            ;;
        yum|dnf)
            if ! rpm -q "$package" &>/dev/null; then
                install_packages "$package"
            fi
            ;;
        pacman)
            if ! pacman -Q "$package" &>/dev/null; then
                install_packages "$package"
            fi
            ;;
    esac
}

# Create directory with proper ownership
create_user_dir() {
    local dir=$1
    local user=$2
    
    mkdir -p "$dir"
    chown "$user:$user" "$dir"
    chmod 755 "$dir"
}

# Safe sed replace (with backup)
safe_sed() {
    local pattern=$1
    local file=$2
    
    if [[ -f "$file" ]]; then
        sed -i.bak "$pattern" "$file"
    fi
}

# Check if we're in a container
in_container() {
    if [[ -f /.dockerenv ]] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        return 0
    fi
    return 1
}

# Print separator line
print_separator() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Confirm action
confirm() {
    local prompt=${1:-"Continue?"}
    local default=${2:-"Y"}
    
    if [[ "$default" == "Y" ]]; then
        read -p "${prompt} [Y/n]: " response
        [[ -z "$response" || "${response,,}" == "y" ]]
    else
        read -p "${prompt} [y/N]: " response
        [[ "${response,,}" == "y" ]]
    fi
}
