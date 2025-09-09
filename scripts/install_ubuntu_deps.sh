#!/bin/bash
#
# LiDiS Ubuntu Build Dependencies Installation Script
# Resolves package naming issues across Ubuntu versions
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect Ubuntu version
detect_ubuntu_version() {
    if [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        UBUNTU_VERSION="$DISTRIB_RELEASE"
        UBUNTU_CODENAME="$DISTRIB_CODENAME"
    elif command -v lsb_release >/dev/null 2>&1; then
        UBUNTU_VERSION=$(lsb_release -rs)
        UBUNTU_CODENAME=$(lsb_release -cs)
    else
        UBUNTU_VERSION="unknown"
        UBUNTU_CODENAME="unknown"
    fi
    
    log_info "Detected Ubuntu $UBUNTU_VERSION ($UBUNTU_CODENAME)"
}

# Update package lists
update_packages() {
    log_info "Updating package lists..."
    sudo apt-get update || {
        log_error "Failed to update package lists"
        exit 1
    }
}

# Install essential build tools
install_build_essentials() {
    log_info "Installing essential build tools..."
    
    local essential_packages=(
        "build-essential"
        "git"
        "wget" 
        "curl"
        "python3"
        "python3-pip"
        "python3-dev"
        "python3-setuptools"
        "flex"
        "bison"
        "libssl-dev"
        "libelf-dev"
        "bc"
        "kmod"
        "cpio"
        "rsync"
        "sudo"
        "fakeroot"
    )
    
    for package in "${essential_packages[@]}"; do
        if ! dpkg -l "$package" >/dev/null 2>&1; then
            log_info "Installing $package..."
            sudo apt-get install -y "$package" || log_warning "Failed to install $package"
        fi
    done
}

# Install distribution build tools
install_distro_tools() {
    log_info "Installing distribution build tools..."
    
    local distro_packages=(
        "debootstrap"
        "squashfs-tools" 
        "genisoimage"
        "mtools"
        "dosfstools"
        "parted"
    )
    
    for package in "${distro_packages[@]}"; do
        if ! dpkg -l "$package" >/dev/null 2>&1; then
            log_info "Installing $package..."
            sudo apt-get install -y "$package" || log_warning "Failed to install $package"
        fi
    done
}

# Install SYSLINUX packages (version-dependent)
install_syslinux() {
    log_info "Installing SYSLINUX packages..."
    
    # Try modern package names first
    local syslinux_packages=(
        "syslinux-common"
        "syslinux-utils" 
        "isolinux"
    )
    
    # For older Ubuntu versions, try alternative names
    local syslinux_alt_packages=(
        "syslinux"
        "syslinux-utils"
        "isolinux"
    )
    
    local installed_any=false
    
    # Try modern packages first
    for package in "${syslinux_packages[@]}"; do
        if apt-cache show "$package" >/dev/null 2>&1; then
            if ! dpkg -l "$package" >/dev/null 2>&1; then
                log_info "Installing $package..."
                if sudo apt-get install -y "$package"; then
                    installed_any=true
                fi
            else
                log_info "$package already installed"
                installed_any=true
            fi
        fi
    done
    
    # If modern packages failed, try alternatives
    if [ "$installed_any" = false ]; then
        log_warning "Modern SYSLINUX packages not found, trying alternatives..."
        for package in "${syslinux_alt_packages[@]}"; do
            if apt-cache show "$package" >/dev/null 2>&1; then
                if ! dpkg -l "$package" >/dev/null 2>&1; then
                    log_info "Installing alternative $package..."
                    sudo apt-get install -y "$package" && installed_any=true
                fi
            fi
        done
    fi
    
    if [ "$installed_any" = false ]; then
        log_error "Could not install SYSLINUX packages. Manual installation may be required."
        return 1
    fi
}

# Install GRUB packages (version and architecture dependent)
install_grub() {
    log_info "Installing GRUB packages..."
    
    local architecture=$(dpkg --print-architecture)
    log_info "Detected architecture: $architecture"
    
    local grub_packages=()
    
    # Architecture-specific GRUB packages
    case "$architecture" in
        "amd64"|"x86_64")
            grub_packages+=(
                "grub-common"
                "grub-efi-amd64"
                "grub-efi-amd64-bin"
                "grub-pc"
                "grub-pc-bin"
                "grub2-common"
            )
            ;;
        "i386"|"x86")
            grub_packages+=(
                "grub-common"
                "grub-efi-ia32"
                "grub-efi-ia32-bin"
                "grub-pc"
                "grub-pc-bin"
                "grub2-common"
            )
            ;;
        "arm64"|"aarch64")
            grub_packages+=(
                "grub-common"
                "grub-efi-arm64"
                "grub-efi-arm64-bin"
                "grub2-common"
            )
            ;;
        *)
            log_warning "Unsupported architecture: $architecture"
            grub_packages+=(
                "grub-common"
                "grub2-common"
            )
            ;;
    esac
    
    # Try to install each GRUB package
    for package in "${grub_packages[@]}"; do
        if apt-cache show "$package" >/dev/null 2>&1; then
            if ! dpkg -l "$package" >/dev/null 2>&1; then
                log_info "Installing $package..."
                sudo apt-get install -y "$package" || log_warning "Failed to install $package (may not be available)"
            else
                log_info "$package already installed"
            fi
        else
            log_warning "Package $package not available in repositories"
        fi
    done
}

# Install additional security tools
install_security_tools() {
    log_info "Installing additional security tools..."
    
    local security_packages=(
        "iptables"
        "iptables-persistent"
        "fail2ban"
        "auditd"
        "apparmor"
        "apparmor-utils"
        "apparmor-profiles"
        "libmagic1"
        "libmagic-dev"
    )
    
    for package in "${security_packages[@]}"; do
        if apt-cache show "$package" >/dev/null 2>&1; then
            if ! dpkg -l "$package" >/dev/null 2>&1; then
                log_info "Installing $package..."
                sudo apt-get install -y "$package" || log_warning "Failed to install $package"
            fi
        fi
    done
}

# Install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."
    
    # Update pip first
    python3 -m pip install --upgrade pip
    
    local python_packages=(
        "numpy"
        "scikit-learn" 
        "aiohttp"
        "psutil"
        "python-magic"
    )
    
    for package in "${python_packages[@]}"; do
        log_info "Installing Python package: $package..."
        python3 -m pip install "$package" || log_warning "Failed to install $package"
    done
}

# Verify installations
verify_installations() {
    log_info "Verifying critical installations..."
    
    local critical_commands=(
        "gcc:build-essential"
        "make:build-essential" 
        "git:git"
        "debootstrap:debootstrap"
        "mksquashfs:squashfs-tools"
        "genisoimage:genisoimage"
        "python3:python3"
        "flex:flex"
        "bison:bison"
    )
    
    local missing_commands=()
    
    for cmd_pkg in "${critical_commands[@]}"; do
        cmd="${cmd_pkg%%:*}"
        pkg="${cmd_pkg##*:}"
        
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands+=("$cmd ($pkg)")
        fi
    done
    
    if [ ${#missing_commands[@]} -ne 0 ]; then
        log_error "Missing critical commands: ${missing_commands[*]}"
        return 1
    else
        log_success "All critical commands available"
        return 0
    fi
}

# Check for alternative bootloader tools if GRUB fails
check_alternatives() {
    log_info "Checking for alternative bootloader tools..."
    
    # Check for extlinux (alternative to syslinux)
    if ! command -v syslinux >/dev/null 2>&1 && ! command -v isolinux >/dev/null 2>&1; then
        if apt-cache show extlinux >/dev/null 2>&1; then
            log_info "Installing extlinux as syslinux alternative..."
            sudo apt-get install -y extlinux
        fi
    fi
    
    # Check for xorriso (alternative to genisoimage)  
    if ! command -v genisoimage >/dev/null 2>&1; then
        if apt-cache show xorriso >/dev/null 2>&1; then
            log_info "Installing xorriso as genisoimage alternative..."
            sudo apt-get install -y xorriso
        fi
    fi
}

# Main installation function
main() {
    log_info "LiDiS Ubuntu Build Dependencies Installation"
    echo "=============================================="
    
    # Check if running as root (should not be)
    if [ "$EUID" -eq 0 ]; then
        log_error "Do not run this script as root. It will use sudo when needed."
        exit 1
    fi
    
    detect_ubuntu_version
    update_packages
    
    log_info "Installing build dependencies in stages..."
    
    install_build_essentials
    install_distro_tools
    
    # Install bootloader tools with error handling
    if ! install_syslinux; then
        log_warning "SYSLINUX installation had issues, continuing..."
    fi
    
    if ! install_grub; then
        log_warning "GRUB installation had issues, continuing..."
    fi
    
    install_security_tools
    install_python_deps
    check_alternatives
    
    log_info "Verifying installations..."
    if verify_installations; then
        log_success "All critical dependencies installed successfully!"
        echo ""
        echo "Build environment is ready. You can now run:"
        echo "  ./scripts/build_lidis.sh"
        echo ""
    else
        log_error "Some dependencies are missing. Check the output above."
        exit 1
    fi
}

# Handle script arguments
case "${1:-install}" in
    "install")
        main
        ;;
    "verify")
        detect_ubuntu_version
        verify_installations
        ;;
    "python-only")
        install_python_deps
        ;;
    "help"|"--help"|"-h")
        echo "LiDiS Ubuntu Dependencies Installer"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  install      Install all dependencies (default)"
        echo "  verify       Verify installations only"
        echo "  python-only  Install Python packages only"
        echo "  help         Show this help"
        ;;
    *)
        log_error "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac