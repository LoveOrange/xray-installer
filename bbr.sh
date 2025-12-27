#!/bin/bash
#===============================================================================
# BBR Installation Module
# Enables Google BBR congestion control algorithm
#
# Usage: sudo bash bbr.sh
#===============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load libraries if available
if [[ -f "${SCRIPT_DIR}/lib/colors.sh" ]]; then
    source "${SCRIPT_DIR}/lib/colors.sh"
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    NC='\033[0m'
fi

if [[ -f "${SCRIPT_DIR}/lib/utils.sh" ]]; then
    source "${SCRIPT_DIR}/lib/utils.sh"
else
    log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
    log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
    log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
    log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
fi

#===============================================================================
# Functions
#===============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_bbr_status() {
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    
    echo ""
    echo -e "${CYAN}Current Configuration:${NC}"
    echo -e "  Congestion Control: ${YELLOW}${current_cc}${NC}"
    echo -e "  Queue Discipline:   ${YELLOW}${current_qdisc}${NC}"
    echo ""
    
    if [[ "$current_cc" == "bbr" ]]; then
        return 0  # BBR is enabled
    fi
    return 1
}

check_kernel_version() {
    local kernel_version=$(uname -r)
    local major_version=$(echo "$kernel_version" | cut -d. -f1)
    local minor_version=$(echo "$kernel_version" | cut -d. -f2)
    
    log_info "Kernel version: ${kernel_version}"
    
    # BBR requires kernel 4.9+
    if [[ $major_version -lt 4 ]] || [[ $major_version -eq 4 && $minor_version -lt 9 ]]; then
        log_error "BBR requires kernel version 4.9 or higher"
        log_info "Your kernel: ${kernel_version}"
        return 1
    fi
    
    return 0
}

check_bbr_module() {
    # Check if BBR module is available
    if modprobe -n tcp_bbr 2>/dev/null; then
        log_info "BBR kernel module is available"
        return 0
    fi
    
    # Check if already loaded
    if lsmod | grep -q tcp_bbr; then
        log_info "BBR kernel module is loaded"
        return 0
    fi
    
    log_warn "BBR kernel module may not be available"
    return 1
}

enable_bbr() {
    log_info "Enabling BBR..."
    
    # Load BBR module
    modprobe tcp_bbr 2>/dev/null || true
    
    # Check if configuration already exists
    if grep -q "net.core.default_qdisc" /etc/sysctl.conf; then
        sed -i 's/^net.core.default_qdisc.*/net.core.default_qdisc=fq/' /etc/sysctl.conf
    else
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    fi
    
    if grep -q "net.ipv4.tcp_congestion_control" /etc/sysctl.conf; then
        sed -i 's/^net.ipv4.tcp_congestion_control.*/net.ipv4.tcp_congestion_control=bbr/' /etc/sysctl.conf
    else
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi
    
    # Apply settings
    sysctl -p 2>/dev/null
    
    # Verify
    if check_bbr_status; then
        log_success "BBR enabled successfully!"
        return 0
    else
        log_warn "BBR configuration added but may require a reboot to take effect"
        return 1
    fi
}

show_available_algorithms() {
    echo ""
    log_info "Available congestion control algorithms:"
    cat /proc/sys/net/ipv4/tcp_available_congestion_control
    echo ""
}

upgrade_kernel_debian() {
    log_info "Upgrading kernel on Debian/Ubuntu..."
    
    # Detect OS
    source /etc/os-release
    
    if [[ "$ID" == "debian" ]]; then
        # Add backports for Debian
        local codename=$(lsb_release -cs 2>/dev/null || echo "bullseye")
        
        if ! grep -q "backports" /etc/apt/sources.list; then
            echo "deb http://deb.debian.org/debian ${codename}-backports main" >> /etc/apt/sources.list
        fi
        
        apt-get update
        apt-get -t ${codename}-backports install -y linux-image-amd64 linux-headers-amd64
        
    elif [[ "$ID" == "ubuntu" ]]; then
        apt-get update
        apt-get install -y --install-recommends linux-generic-hwe-$(lsb_release -rs)
    fi
    
    log_success "Kernel upgraded. Please reboot and run this script again."
}

#===============================================================================
# Main
#===============================================================================

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              BBR Congestion Control Installer              ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    check_root
    
    # Check current status
    if check_bbr_status; then
        log_success "BBR is already enabled!"
        show_available_algorithms
        exit 0
    fi
    
    # Check kernel version
    if ! check_kernel_version; then
        echo ""
        read -p "Would you like to upgrade the kernel? [y/N]: " upgrade
        if [[ "${upgrade,,}" == "y" ]]; then
            upgrade_kernel_debian
            exit 0
        else
            log_error "Cannot enable BBR with current kernel"
            exit 1
        fi
    fi
    
    # Check BBR module
    check_bbr_module
    
    # Enable BBR
    enable_bbr
    
    # Show final status
    echo ""
    log_info "Final verification:"
    
    if lsmod | grep -q tcp_bbr; then
        echo -e "  BBR Module:  ${GREEN}Loaded${NC}"
    else
        echo -e "  BBR Module:  ${YELLOW}Not loaded (may need reboot)${NC}"
    fi
    
    local cc=$(sysctl -n net.ipv4.tcp_congestion_control)
    if [[ "$cc" == "bbr" ]]; then
        echo -e "  TCP CC:      ${GREEN}${cc}${NC}"
    else
        echo -e "  TCP CC:      ${YELLOW}${cc}${NC}"
    fi
    
    local qdisc=$(sysctl -n net.core.default_qdisc)
    if [[ "$qdisc" == "fq" ]]; then
        echo -e "  Queue Disc:  ${GREEN}${qdisc}${NC}"
    else
        echo -e "  Queue Disc:  ${YELLOW}${qdisc}${NC}"
    fi
    
    echo ""
    show_available_algorithms
}

main "$@"
