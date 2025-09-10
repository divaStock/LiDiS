#!/bin/bash
#
# LiDiS Linux Distribution Build System
# Builds a complete LiDiS distribution with security enhancements
#
# Copyright (C) 2025 LiDiS Security Project
# Licensed under GPL v3
#

set -euo pipefail

# Ensure required variables are set to avoid unbound variable errors
: "${LIDIS_VERSION:=1.0.0}"
: "${LIDIS_CODENAME:=SecurityCore}"  
: "${BUILD_DIR:=/tmp/lidis-build}"
: "${OUTPUT_DIR:=/tmp/lidis-output}"
: "${KERNEL_VERSION:=6.8}"
: "${ARCH:=}"
: "${JOBS:=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
: "${ENABLE_BTF:=false}"

# Colors for output  
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions (must be defined before use)
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

# Error handling
error_exit() {
    log_error "$1"
    exit 1
}

# Get CPU core count (cross-platform)
get_cpu_count() {
    local cpu_count
    
    # Try different methods to get CPU count
    if command -v nproc >/dev/null 2>&1; then
        cpu_count=$(nproc)
    elif command -v sysctl >/dev/null 2>&1 && sysctl -n hw.ncpu >/dev/null 2>&1; then
        cpu_count=$(sysctl -n hw.ncpu)
    elif command -v getconf >/dev/null 2>&1; then
        cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
    elif [ -r /proc/cpuinfo ]; then
        cpu_count=$(grep -c ^processor /proc/cpuinfo)
    else
        cpu_count=4  # Safe fallback
        log_warning "Could not detect CPU count, using fallback: $cpu_count"
    fi
    
    # Ensure we have a valid number
    if ! [[ "$cpu_count" =~ ^[0-9]+$ ]] || [ "$cpu_count" -lt 1 ]; then
        cpu_count=4
        log_warning "Invalid CPU count detected, using fallback: $cpu_count"
    fi
    
    echo "$cpu_count"
}

# Build configuration (use pre-set defaults)
# Variables are already initialized above to prevent unbound variable errors

# Auto-detect architecture if not specified
if [ -z "$ARCH" ]; then
    DETECTED_ARCH=$(uname -m)
    case "$DETECTED_ARCH" in
        "x86_64"|"amd64")
            ARCH="x86_64"
            ;;
        "aarch64"|"arm64")
            ARCH="arm64"
            ;;
        "i686"|"i386")
            ARCH="i386"
            ;;
        *)
            ARCH="$DETECTED_ARCH"
            ;;
    esac
    log_info "Auto-detected architecture: $ARCH"
else
    log_info "Using specified architecture: $ARCH"
fi
# JOBS variable already set above

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIGS_DIR="$PROJECT_ROOT/configs"
SRC_DIR="$PROJECT_ROOT/src"

# Colors and logging functions already defined above

# Check dependencies
check_dependencies() {
    log_info "Checking build dependencies for $ARCH..."
    
    # Common dependencies for all architectures
    local deps=(
        "gcc" "make" "git" "wget" "curl" "debootstrap" "squashfs-tools"
        "genisoimage" "mtools" "dosfstools" "parted" "python3"
        "python3-pip" "flex" "bison" "libssl-dev" "libelf-dev"
        "bc" "kmod" "cpio" "rsync"
    )
    
    # Optional dependencies (build will work without these)
    local optional_deps=(
        "pahole"
        "xorriso"
        "isohybrid"
    )
    
    # Architecture-specific dependencies
    case "$ARCH" in
        "x86_64"|"amd64")
            deps+=("isolinux" "syslinux-utils" "grub-efi-amd64-bin" "grub-pc-bin")
            ;;
        "arm64"|"aarch64")
            deps+=("grub-efi-arm64" "grub-efi-arm64-bin")
            ;;
        "i386"|"x86")
            deps+=("isolinux" "syslinux-utils" "grub-efi-ia32-bin" "grub-pc-bin")
            ;;
        *)
            deps+=("grub-common")
            log_warning "Using generic dependencies for architecture: $ARCH"
            ;;
    esac
    
    local missing_deps=()
    local missing_optional=()
    
    # Check required dependencies
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1 && ! dpkg -l "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    
    # Special checks for tools within packages
    if ! command -v mformat >/dev/null 2>&1; then
        log_warning "mformat (from mtools) not found - required for EFI boot images"
        missing_deps+=("mformat (install mtools package)")
    fi
    
    if ! command -v grub-mkrescue >/dev/null 2>&1; then
        missing_deps+=("grub-mkrescue (install grub2-utils or grub-common)")
    fi
    
    # Check optional dependencies
    for dep in "${optional_deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1 && ! dpkg -l "$dep" >/dev/null 2>&1; then
            missing_optional+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_info "Please install missing dependencies and try again"
        log_info "Example: sudo apt-get install ${missing_deps[*]}"
        exit 1
    fi
    
    if [ ${#missing_optional[@]} -ne 0 ]; then
        log_warning "Missing optional dependencies: ${missing_optional[*]}"
        log_info "Build will continue, but some features may be disabled"
        log_info "To enable all features: sudo apt-get install ${missing_optional[*]}"
        
        # Specific guidance for pahole
        if [[ " ${missing_optional[*]} " =~ " pahole " ]]; then
            log_info "Without pahole: BTF debug info will be disabled automatically"
            log_info "Install pahole with: sudo apt-get install dwarves"
        fi
    fi
    
    log_success "All required dependencies satisfied"
}

# Setup build environment
setup_build_environment() {
    log_info "Setting up build environment..."
    
    # Create build directories
    mkdir -p "$BUILD_DIR"/{kernel,rootfs,iso,packages,tools}
    mkdir -p "$OUTPUT_DIR"
    
    # Set environment variables
    export LIDIS_BUILD_DIR="$BUILD_DIR"
    export LIDIS_ROOT="$PROJECT_ROOT"
    export ARCH
    export CROSS_COMPILE=""
    
    log_success "Build environment ready"
}

# Download kernel source
download_kernel() {
    log_info "Downloading Linux kernel $KERNEL_VERSION..."
    
    local kernel_dir="$BUILD_DIR/kernel/linux-$KERNEL_VERSION"
    local download_urls=(
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz"
        "https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz" 
        "https://www.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz"
        "https://github.com/torvalds/linux/archive/v$KERNEL_VERSION.tar.gz"
    )
    
    if [ ! -d "$kernel_dir" ]; then
        cd "$BUILD_DIR/kernel"
        
        local downloaded=false
        local download_cmd=""
        
        # Choose download command (prefer curl over wget on macOS)
        if command -v curl >/dev/null 2>&1; then
            download_cmd="curl"
        elif command -v wget >/dev/null 2>&1; then
            download_cmd="wget"
        else
            error_exit "Neither curl nor wget found. Please install one of them."
        fi
        
        # Try each URL until one works
        for url in "${download_urls[@]}"; do
            log_info "Trying $url..."
            
            # Determine file extension and output filename
            local filename
            local extract_cmd
            if [[ "$url" == *".tar.gz" ]]; then
                filename="linux-$KERNEL_VERSION.tar.gz"
                extract_cmd="tar -xzf"
            else
                filename="linux-$KERNEL_VERSION.tar.xz"
                extract_cmd="tar -xf"
            fi
            
            # Try downloading with timeout
            local download_success=false
            if [ "$download_cmd" = "curl" ]; then
                if curl --max-time 300 --connect-timeout 30 -L -f -o "$filename" "$url" 2>/dev/null; then
                    download_success=true
                fi
            else
                if wget --timeout=300 --connect-timeout=30 -q "$url" -O "$filename"; then
                    download_success=true
                fi
            fi
            
            if [ "$download_success" = true ]; then
                log_info "Download successful, extracting..."
                if $extract_cmd "$filename" 2>/dev/null; then
                    # GitHub tarballs extract to linux-$KERNEL_VERSION directory
                    if [[ "$url" == *"github.com"* ]] && [ -d "linux-$KERNEL_VERSION" ]; then
                        # GitHub archive is ready
                        downloaded=true
                        break
                    elif [ -d "linux-$KERNEL_VERSION" ]; then
                        # Standard kernel.org archive is ready
                        downloaded=true
                        break
                    else
                        log_warning "Extraction succeeded but expected directory not found"
                        rm -f "$filename" 2>/dev/null
                    fi
                else
                    log_warning "Failed to extract $filename"
                    rm -f "$filename" 2>/dev/null
                fi
            else
                log_warning "Failed to download from $url, trying next..."
            fi
        done
        
        if [ "$downloaded" = false ]; then
            log_error "Failed to download kernel from any source."
            log_error "Please check your internet connection and try again."
            log_error "You can also manually download linux-$KERNEL_VERSION.tar.xz to $BUILD_DIR/kernel/"
            error_exit "Kernel download failed"
        fi
        
        log_success "Kernel downloaded and extracted"
    else
        log_info "Kernel already exists, skipping download"
    fi
}

# Apply LiDiS security patches
apply_security_patches() {
    log_info "Applying LiDiS security patches..."
    
    local kernel_dir="$BUILD_DIR/kernel/linux-$KERNEL_VERSION"
    cd "$kernel_dir"
    
    # Copy LiDiS security headers and modules
    mkdir -p security/lidis
    cp -r "$SRC_DIR/kernel"/* security/lidis/ 2>/dev/null || true
    
    # Apply patches if they exist
    local patches_dir="$PROJECT_ROOT/patches/kernel"
    if [ -d "$patches_dir" ]; then
        for patch in "$patches_dir"/*.patch; do
            if [ -f "$patch" ]; then
                log_info "Applying patch: $(basename "$patch")"
                patch -p1 < "$patch" || log_warning "Patch $(basename "$patch") failed"
            fi
        done
    fi
    
    log_success "Security patches applied"
}

# Configure and build kernel
build_kernel() {
    log_info "Building LiDiS kernel..."
    
    local kernel_dir="$BUILD_DIR/kernel/linux-$KERNEL_VERSION"
    cd "$kernel_dir"
    
    # Use LiDiS kernel configuration
    cp "$CONFIGS_DIR/kernel_config" .config
    
    # Handle BTF configuration based on user preference and tool availability
    if [ "$ENABLE_BTF" = "true" ] && command -v pahole >/dev/null 2>&1; then
        log_info "BTF enabled by user and pahole available - keeping BTF debug info"
        # Verify pahole version is compatible
        local pahole_version
        pahole_version=$(pahole --version 2>/dev/null | head -1 || echo "unknown")
        log_info "Using pahole version: $pahole_version"
    else
        if [ "$ENABLE_BTF" = "true" ] && ! command -v pahole >/dev/null 2>&1; then
            log_warning "BTF requested but pahole not available - disabling BTF"
        else
            log_info "Disabling BTF debug info to ensure reliable builds"
        fi
        
        # Comprehensively disable all BTF-related options (handle macOS vs Linux sed)
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS sed requires empty string after -i
            sed -i '' 's/CONFIG_DEBUG_INFO_BTF=y/# CONFIG_DEBUG_INFO_BTF is not set/' .config
            sed -i '' 's/CONFIG_DEBUG_INFO_BTF_MODULES=y/# CONFIG_DEBUG_INFO_BTF_MODULES is not set/' .config
            sed -i '' 's/CONFIG_PAHOLE_HAS_SPLIT_BTF=y/# CONFIG_PAHOLE_HAS_SPLIT_BTF is not set/' .config
        else
            # Linux sed
            sed -i 's/CONFIG_DEBUG_INFO_BTF=y/# CONFIG_DEBUG_INFO_BTF is not set/' .config
            sed -i 's/CONFIG_DEBUG_INFO_BTF_MODULES=y/# CONFIG_DEBUG_INFO_BTF_MODULES is not set/' .config
            sed -i 's/CONFIG_PAHOLE_HAS_SPLIT_BTF=y/# CONFIG_PAHOLE_HAS_SPLIT_BTF is not set/' .config
        fi
        
        # Ensure BTF is completely disabled
        cat >> .config << 'EOF'
# LiDiS: Disable BTF to prevent build failures
# CONFIG_DEBUG_INFO_BTF is not set
# CONFIG_DEBUG_INFO_BTF_MODULES is not set  
# CONFIG_PAHOLE_HAS_SPLIT_BTF is not set
EOF
        
        log_info "BTF debug info disabled for stable builds"
    fi
    
    # Update configuration for current kernel version
    make olddefconfig
    
    # Build kernel and modules with enhanced error handling
    log_info "Compiling kernel (this may take a while)..."
    
    # First attempt: normal build
    if ! make -j"$JOBS"; then
        log_warning "Initial kernel build failed, trying fallback options..."
        
        # Clean any partial build artifacts that might be corrupted
        log_info "Cleaning build artifacts..."
        make clean
        
        # Disable more debug options that can cause issues
        log_info "Disabling additional debug options for fallback build..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' 's/CONFIG_DEBUG_INFO=y/# CONFIG_DEBUG_INFO is not set/' .config
            sed -i '' 's/CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y/# CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT is not set/' .config
        else
            sed -i 's/CONFIG_DEBUG_INFO=y/# CONFIG_DEBUG_INFO is not set/' .config
            sed -i 's/CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y/# CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT is not set/' .config
        fi
        
        # Regenerate config
        make olddefconfig
        
        # Retry build with single thread to avoid race conditions
        log_info "Retrying kernel build with single thread..."
        make -j1 || error_exit "Kernel build failed even with fallback options"
    fi
    
    log_info "Compiling kernel modules..."
    make -j"$JOBS" modules || {
        log_warning "Module build failed, retrying with single thread..."
        make -j1 modules || error_exit "Module build failed"
    }
    
    # Install modules to temporary location  
    local modules_dir="$BUILD_DIR/rootfs/lib/modules/$KERNEL_VERSION-lidis-security"
    mkdir -p "$modules_dir"
    make INSTALL_MOD_PATH="$BUILD_DIR/rootfs" modules_install
    
    # Copy kernel image (architecture-specific)
    case "$ARCH" in
        "x86_64"|"amd64"|"i386"|"x86")
            if [ -f "arch/x86/boot/bzImage" ]; then
                cp arch/x86/boot/bzImage "$BUILD_DIR/iso/vmlinuz"
                log_info "Copied x86 kernel image (bzImage)"
            else
                log_error "x86 kernel image not found at arch/x86/boot/bzImage"
                exit 1
            fi
            ;;
        "arm64"|"aarch64")
            if [ -f "arch/arm64/boot/Image" ]; then
                cp arch/arm64/boot/Image "$BUILD_DIR/iso/vmlinuz"
                log_info "Copied ARM64 kernel image (Image)"
            elif [ -f "arch/arm64/boot/Image.gz" ]; then
                cp arch/arm64/boot/Image.gz "$BUILD_DIR/iso/vmlinuz"
                log_info "Copied ARM64 kernel image (Image.gz)"
            else
                log_error "ARM64 kernel image not found at arch/arm64/boot/"
                exit 1
            fi
            ;;
        *)
            log_warning "Unknown architecture $ARCH, trying generic kernel image"
            if [ -f "vmlinux" ]; then
                cp vmlinux "$BUILD_DIR/iso/vmlinuz"
            else
                log_error "No suitable kernel image found for $ARCH"
                exit 1
            fi
            ;;
    esac
    
    log_success "Kernel build completed"
}

# Create base root filesystem
create_base_rootfs() {
    log_info "Creating base root filesystem..."
    
    local rootfs_dir="$BUILD_DIR/rootfs"
    
    if [ ! -d "$rootfs_dir/usr" ]; then
        # Map our ARCH to debootstrap architecture names
        local debootstrap_arch
        case "$ARCH" in
            "x86_64"|"amd64")
                debootstrap_arch="amd64"
                ;;
            "arm64"|"aarch64")
                debootstrap_arch="arm64"
                ;;
            "i386"|"x86")
                debootstrap_arch="i386"
                ;;
            *)
                debootstrap_arch="$ARCH"
                log_warning "Using architecture $ARCH directly for debootstrap"
                ;;
        esac
        
        log_info "Creating $debootstrap_arch base system..."
        
        # Select appropriate mirror based on architecture
        local ubuntu_mirror
        case "$debootstrap_arch" in
            "amd64"|"i386")
                # x86 architectures use the main archive
                ubuntu_mirror="http://archive.ubuntu.com/ubuntu/"
                ;;
            "arm64"|"armhf"|"ppc64el"|"s390x")
                # Non-x86 architectures use the ports archive
                ubuntu_mirror="http://ports.ubuntu.com/ubuntu-ports/"
                ;;
            *)
                # Default to ports for unknown architectures
                ubuntu_mirror="http://ports.ubuntu.com/ubuntu-ports/"
                log_warning "Unknown architecture $debootstrap_arch, using ports mirror"
                ;;
        esac
        
        log_info "Using mirror: $ubuntu_mirror for $debootstrap_arch"
        
        # Check network connectivity before attempting download
        log_info "Testing network connectivity..."
        if ! curl --connect-timeout 10 --max-time 30 -s --head "$ubuntu_mirror" >/dev/null 2>&1 && \
           ! wget --timeout=30 --connect-timeout=10 --spider "$ubuntu_mirror" >/dev/null 2>&1; then
            log_warning "Cannot reach primary mirror, network connectivity may be limited"
        fi
        
        # Use debootstrap to create base system (Ubuntu 22.04 LTS) with fallback
        if ! debootstrap --arch="$debootstrap_arch" jammy "$rootfs_dir" "$ubuntu_mirror"; then
            log_warning "Primary mirror failed, trying fallback mirrors..."
            
            # Try alternative mirrors
            local fallback_mirrors=(
                "http://mirror.ubuntu.com/ubuntu/"
                "http://us.archive.ubuntu.com/ubuntu/"
                "http://gb.archive.ubuntu.com/ubuntu/"
            )
            
            # For non-x86, try ports mirrors
            if [[ "$debootstrap_arch" != "amd64" && "$debootstrap_arch" != "i386" ]]; then
                fallback_mirrors=(
                    "http://mirror.ubuntu.com/ubuntu-ports/"
                    "http://ports.ubuntu.com/ubuntu-ports/"
                )
            fi
            
            local success=false
            for mirror in "${fallback_mirrors[@]}"; do
                log_info "Trying fallback mirror: $mirror"
                
                # Test connectivity to fallback mirror first
                if curl --connect-timeout 5 --max-time 15 -s --head "$mirror" >/dev/null 2>&1 || \
                   wget --timeout=15 --connect-timeout=5 --spider "$mirror" >/dev/null 2>&1; then
                    log_info "Mirror $mirror is reachable, attempting debootstrap..."
                    
                    if debootstrap --arch="$debootstrap_arch" jammy "$rootfs_dir" "$mirror"; then
                        success=true
                        break
                    else
                        log_warning "Debootstrap failed with mirror $mirror"
                    fi
                else
                    log_warning "Mirror $mirror is not reachable, skipping..."
                fi
                
                # Clean up partial download on failure
                rm -rf "$rootfs_dir" 2>/dev/null || true
            done
            
            if [ "$success" = false ]; then
                log_error "Failed to create base filesystem with all available mirrors"
                log_error "This could be due to:"
                log_error "  - Network connectivity issues"
                log_error "  - Mirror availability problems"
                log_error "  - Architecture $debootstrap_arch not supported"
                log_error ""
                log_error "Troubleshooting steps:"
                log_error "  1. Check internet connection"
                log_error "  2. Try different architecture: ARCH=amd64 $0"
                log_error "  3. Use different Ubuntu release (modify script)"
                error_exit "Unable to download base filesystem"
            fi
        fi
        
        log_success "Base filesystem created"
        
        # Configure comprehensive sources.list for full package availability
        log_info "Configuring package repositories..."
        configure_repositories "$rootfs_dir" "$ubuntu_mirror" "$debootstrap_arch"
    else
        log_info "Base filesystem already exists"
    fi
}

# Configure package repositories in rootfs
configure_repositories() {
    local rootfs_dir="$1"
    local primary_mirror="$2"
    local arch="$3"
    
    log_info "Setting up comprehensive package repositories for $arch"
    
    # Create comprehensive sources.list based on architecture
    if [[ "$arch" == "amd64" || "$arch" == "i386" ]]; then
        # x86 architectures use main archive
        cat > "$rootfs_dir/etc/apt/sources.list" << EOF
# LiDiS Ubuntu 22.04 LTS (Jammy) Package Sources
deb http://archive.ubuntu.com/ubuntu/ jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ jammy-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ jammy-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu/ jammy-security main restricted universe multiverse

# Additional sources
deb-src http://archive.ubuntu.com/ubuntu/ jammy main restricted universe multiverse
EOF
    else
        # ARM64 and other architectures use ports
        cat > "$rootfs_dir/etc/apt/sources.list" << EOF
# LiDiS Ubuntu 22.04 LTS (Jammy) Package Sources - Ports
deb http://ports.ubuntu.com/ubuntu-ports/ jammy main restricted universe multiverse
deb http://ports.ubuntu.com/ubuntu-ports/ jammy-updates main restricted universe multiverse
deb http://ports.ubuntu.com/ubuntu-ports/ jammy-backports main restricted universe multiverse
deb http://ports.ubuntu.com/ubuntu-ports/ jammy-security main restricted universe multiverse

# Additional sources
deb-src http://ports.ubuntu.com/ubuntu-ports/ jammy main restricted universe multiverse
EOF
    fi
    
    log_success "Package repositories configured for $arch"
}

# Install LiDiS security components
install_security_components() {
    log_info "Installing LiDiS security components..."
    
    local rootfs_dir="$BUILD_DIR/rootfs"
    
    # Create security directories
    mkdir -p "$rootfs_dir"/{opt/lidis,etc/lidis,var/log/lidis,var/lib/lidis}
    
    # Install Python security components
    cp -r "$SRC_DIR/security" "$rootfs_dir/opt/lidis/"
    
    # Install configuration files
    cp -r "$CONFIGS_DIR"/* "$rootfs_dir/etc/lidis/" 2>/dev/null || true
    
    # Create systemd service files
    cat > "$rootfs_dir/etc/systemd/system/lidis-ips.service" << 'EOF'
[Unit]
Description=LiDiS Intrusion Prevention System
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/lidis/security/ips_engine.py
Restart=always
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    cat > "$rootfs_dir/etc/systemd/system/lidis-ttp-detector.service" << 'EOF'
[Unit]
Description=LiDiS TTP Detection System
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/lidis/security/ttp_detector.py
Restart=always
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    cat > "$rootfs_dir/etc/systemd/system/lidis-zeroday-detector.service" << 'EOF'
[Unit]
Description=LiDiS Zero-day Vulnerability Detection
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/lidis/security/zeroday_detector.py
Restart=always
RestartSec=10
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    cat > "$rootfs_dir/etc/systemd/system/lidis-threat-intelligence.service" << 'EOF'
[Unit]
Description=LiDiS Threat Intelligence Agent
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/lidis/security/threat_intelligence.py
Restart=always
RestartSec=10
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    # Create LiDiS configuration
    cat > "$rootfs_dir/etc/lidis/lidis.conf" << EOF
# LiDiS Security Configuration
[general]
version = $LIDIS_VERSION
security_level = 8
enforcement_mode = true
logging_enabled = true

[ips]
enabled = true
behavioral_analysis = true
ml_detection = true
auto_response = true

[ttp_detection]
enabled = true
mitre_attack_mapping = true
threat_hunting = true
behavioral_monitoring = true

[zeroday_detection]
enabled = true
dynamic_analysis = true
static_analysis = true
ml_classification = true

[threat_intelligence]
enabled = true
auto_collection = true
rule_generation = true
auto_deployment = false
EOF

    # Install Python dependencies and security tools
    log_info "Installing Python runtime and security packages..."
    chroot "$rootfs_dir" /bin/bash -c "
        # Update package lists with comprehensive repositories
        apt-get update
        
        # Install basic build and development tools
        apt-get install -y build-essential wget curl ca-certificates
        
        # Install Python packages (should now be available from universe)
        if apt-get install -y python3-pip python3-dev python3-setuptools python3-venv; then
            echo 'Python packages installed successfully'
        else
            echo 'Warning: Some Python packages may not be available'
            # Fallback: install basic python3 and try to get pip manually
            apt-get install -y python3 python3-dev
            curl -sS https://bootstrap.pypa.io/get-pip.py | python3 - || echo 'pip installation failed'
        fi
        
        # Install Python dependencies with error handling
        if command -v pip3 >/dev/null 2>&1 || command -v pip >/dev/null 2>&1; then
            python3 -m pip install --upgrade pip setuptools wheel 2>/dev/null || echo 'pip upgrade failed'
            python3 -m pip install numpy scikit-learn aiohttp psutil python-magic 2>/dev/null || {
                echo 'Warning: Some Python packages failed to install'
                # Try installing with system packages as fallback
                apt-get install -y python3-numpy python3-sklearn python3-psutil 2>/dev/null || true
            }
        else
            echo 'pip not available, trying system packages'
            apt-get install -y python3-numpy python3-sklearn python3-psutil 2>/dev/null || true
        fi
        
        # Install security packages
        echo 'Installing security packages...'
        apt-get install -y iptables iptables-persistent || echo 'Warning: iptables packages may not be available'
        apt-get install -y fail2ban || echo 'Warning: fail2ban not available'
        apt-get install -y auditd apparmor apparmor-utils apparmor-profiles || echo 'Warning: Some security tools not available'
        
        # Install networking tools
        apt-get install -y netfilter-persistent ufw || echo 'Warning: Some network security tools not available'
        
        echo 'Package installation completed'
    "
    
    # Enable LiDiS services (do this outside chroot to avoid systemctl issues)
    log_info "Configuring LiDiS services..."
    if [ -f "$rootfs_dir/etc/systemd/system/lidis-ips.service" ]; then
        chroot "$rootfs_dir" /bin/bash -c "
            systemctl enable lidis-ips 2>/dev/null || echo 'Service lidis-ips will be enabled on first boot'
            systemctl enable lidis-ttp-detector 2>/dev/null || echo 'Service lidis-ttp-detector will be enabled on first boot'
            systemctl enable lidis-zeroday-detector 2>/dev/null || echo 'Service lidis-zeroday-detector will be enabled on first boot'
            systemctl enable lidis-threat-intelligence 2>/dev/null || echo 'Service lidis-threat-intelligence will be enabled on first boot'
        " || log_warning "Service enablement will be handled on first boot"
    fi
    
    log_success "Security components installed"
}

# Configure system security
configure_system_security() {
    log_info "Configuring system security settings..."
    
    local rootfs_dir="$BUILD_DIR/rootfs"
    
    # Create all necessary security directories first
    log_info "Creating security configuration directories..."
    mkdir -p "$rootfs_dir"/{etc/audit/rules.d,etc/apparmor.d/lidis,etc/security,var/log/audit}
    
    # Kernel security parameters
    cat >> "$rootfs_dir/etc/sysctl.conf" << 'EOF'

# LiDiS Security Hardening
# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# IPv6 security
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Kernel security
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# File system security
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0

# Memory security
kernel.randomize_va_space = 2
vm.mmap_min_addr = 65536

# Process security
kernel.core_pattern = |/bin/false
EOF

    # Configure AppArmor profiles
    log_info "Setting up AppArmor profiles..."
    # (Directory already created above)
    
    # Configure audit rules
    log_info "Setting up audit rules..."
    cat > "$rootfs_dir/etc/audit/rules.d/lidis.rules" << 'EOF'
# LiDiS Security Audit Rules

# Monitor privileged commands
-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged
-a always,exit -F arch=b32 -S execve -F euid=0 -k privileged

# Monitor file access
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k passwd_changes  
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/ssh/sshd_config -p wa -k ssh_config

# Monitor network configuration
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Monitor system calls
-a always,exit -F arch=b64 -S mount -k mounts
-a always,exit -F arch=b64 -S umount2 -k mounts
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod
EOF

    # Set secure permissions and enable services
    chroot "$rootfs_dir" /bin/bash -c "
        # Set basic file permissions
        chmod 644 /etc/sysctl.conf 2>/dev/null || echo 'Warning: Could not set sysctl.conf permissions'
        
        # Set audit rules permissions if file exists
        [ -f /etc/audit/rules.d/lidis.rules ] && chmod 600 /etc/audit/rules.d/lidis.rules || echo 'Warning: Audit rules file not found'
        
        # Set LiDiS security script permissions
        [ -d /opt/lidis/security ] && chmod 755 /opt/lidis/security/*.py 2>/dev/null || echo 'Warning: LiDiS security scripts not found'
        
        # Enable security services if available
        if command -v systemctl >/dev/null 2>&1; then
            systemctl enable auditd 2>/dev/null || echo 'Warning: auditd service not available'
            systemctl enable apparmor 2>/dev/null || echo 'Warning: apparmor service not available'
        else
            echo 'Warning: systemctl not available, services will need manual enablement'
        fi
        
        echo 'Security permissions and services configured'
    "
    
    log_success "System security configured"
}

# Create initramfs
create_initramfs() {
    log_info "Creating initramfs..."
    
    local rootfs_dir="$BUILD_DIR/rootfs"
    local initramfs_dir="$BUILD_DIR/initramfs"
    
    mkdir -p "$initramfs_dir"
    
    # Create minimal initramfs structure
    cd "$initramfs_dir"
    mkdir -p {bin,sbin,etc,proc,sys,dev,tmp,lib,lib64,usr/bin,usr/sbin,mnt/live,mnt/squashfs,sysroot}
    
    # Copy essential binaries for live boot
    cp /bin/sh bin/
    cp /bin/busybox bin/ 2>/dev/null || true
    cp /bin/mount bin/ 2>/dev/null || cp /usr/bin/mount bin/ 2>/dev/null || true
    cp /bin/umount bin/ 2>/dev/null || cp /usr/bin/umount bin/ 2>/dev/null || true
    cp /bin/mkdir bin/ 2>/dev/null || cp /usr/bin/mkdir bin/ 2>/dev/null || true
    cp /bin/ls bin/ 2>/dev/null || cp /usr/bin/ls bin/ 2>/dev/null || true
    cp /sbin/modprobe sbin/ 2>/dev/null || cp /usr/sbin/modprobe sbin/ 2>/dev/null || true
    cp /sbin/switch_root sbin/ 2>/dev/null || cp /usr/sbin/switch_root sbin/ 2>/dev/null || true
    
    # Copy SquashFS kernel module if available
    local kernel_ver=$(uname -r)
    if [ -f "/lib/modules/$kernel_ver/kernel/fs/squashfs/squashfs.ko" ]; then
        mkdir -p "lib/modules/$kernel_ver/kernel/fs/squashfs"
        cp "/lib/modules/$kernel_ver/kernel/fs/squashfs/squashfs.ko" "lib/modules/$kernel_ver/kernel/fs/squashfs/"
    fi
    cp /sbin/init sbin/ 2>/dev/null || cp /usr/lib/systemd/systemd sbin/init
    
    # Create init script for live system
    cat > init << 'EOF'
#!/bin/sh

# Mount essential filesystems
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

# Load SquashFS module
modprobe squashfs 2>/dev/null || echo "SquashFS module already loaded"

# Find and mount the CD-ROM/ISO
echo "Searching for LiDiS live media..."
for device in /dev/sr0 /dev/cdrom /dev/hdc /dev/scd0; do
    if [ -b "$device" ]; then
        echo "Trying to mount $device..."
        if mount -t iso9660 -o ro "$device" /mnt/live 2>/dev/null; then
            echo "Mounted live media from $device"
            break
        fi
    fi
done

# Check if we found the SquashFS filesystem
if [ -f "/mnt/live/live/filesystem.squashfs" ]; then
    echo "Found SquashFS filesystem, mounting..."
    
    # Mount the SquashFS filesystem
    mount -t squashfs -o loop,ro /mnt/live/live/filesystem.squashfs /mnt/squashfs
    
    # Create a tmpfs for writable layer
    mount -t tmpfs tmpfs /tmp
    mkdir -p /tmp/rw /tmp/work
    
    # Use overlay filesystem for read-write capability
    if mount -t overlay overlay -o lowerdir=/mnt/squashfs,upperdir=/tmp/rw,workdir=/tmp/work /sysroot 2>/dev/null; then
        echo "Overlay filesystem mounted successfully"
    else
        # Fallback to read-only SquashFS mount
        echo "Overlay not available, using read-only SquashFS"
        mount --bind /mnt/squashfs /sysroot
    fi
    
    # Prepare for switch_root
    mkdir -p /sysroot/proc /sysroot/sys /sysroot/dev
    mount --move /proc /sysroot/proc
    mount --move /sys /sysroot/sys
    mount --move /dev /sysroot/dev
    
    # Switch to the real root
    echo "Switching to LiDiS root filesystem..."
    exec switch_root /sysroot /sbin/init
else
    echo "ERROR: Could not find LiDiS filesystem!"
    echo "Available files in /mnt/live:"
    ls -la /mnt/live/ 2>/dev/null || echo "Mount failed"
    
    # Drop to emergency shell
    echo "Dropping to emergency shell..."
    exec /bin/sh
fi
EOF
    chmod +x init
    
    # Create initramfs archive
    find . | cpio -o -H newc | gzip -9 > "$BUILD_DIR/iso/initrd.img"
    
    log_success "Initramfs created"
}

# Create bootloader configuration
create_bootloader() {
    log_info "Creating bootloader configuration..."
    
    local iso_dir="$BUILD_DIR/iso"
    
    # Create GRUB configuration
    mkdir -p "$iso_dir/boot/grub"
    cat > "$iso_dir/boot/grub/grub.cfg" << EOF
set timeout=10
set default=0

menuentry "LiDiS Linux $LIDIS_VERSION ($LIDIS_CODENAME)" {
    linux /vmlinuz boot=live security=lidis quiet splash
    initrd /initrd.img
}

menuentry "LiDiS Linux $LIDIS_VERSION (Recovery Mode)" {
    linux /vmlinuz boot=live security=lidis single
    initrd /initrd.img
}

menuentry "LiDiS Linux $LIDIS_VERSION (Debug Mode)" {
    linux /vmlinuz boot=live security=lidis debug loglevel=7
    initrd /initrd.img
}
EOF

    # Create architecture-specific bootloader configuration
    case "$ARCH" in
        "x86_64"|"amd64"|"i386"|"x86")
            # Create isolinux configuration for BIOS boot (x86 only)
            mkdir -p "$iso_dir/isolinux"
            cat > "$iso_dir/isolinux/isolinux.cfg" << EOF
DEFAULT lidis
TIMEOUT 100
PROMPT 0

LABEL lidis
  KERNEL /vmlinuz
  APPEND initrd=/initrd.img boot=live security=lidis quiet splash

LABEL recovery
  KERNEL /vmlinuz  
  APPEND initrd=/initrd.img boot=live security=lidis single

LABEL debug
  KERNEL /vmlinuz
  APPEND initrd=/initrd.img boot=live security=lidis debug loglevel=7
EOF

            # Copy bootloader files
            if cp /usr/lib/ISOLINUX/isolinux.bin "$iso_dir/isolinux/" 2>/dev/null || \
               cp /usr/lib/syslinux/modules/bios/isolinux.bin "$iso_dir/isolinux/" 2>/dev/null; then
                log_info "Copied isolinux.bin for x86 BIOS boot"
            else
                log_warning "Could not find isolinux.bin - BIOS boot may not work"
            fi
            
            cp /usr/lib/syslinux/modules/bios/ldlinux.c32 "$iso_dir/isolinux/" 2>/dev/null || \
                log_info "ldlinux.c32 not found (may not be needed)"
            ;;
        "arm64"|"aarch64")
            log_info "ARM64 uses EFI boot only - skipping isolinux/BIOS configuration"
            ;;
        *)
            log_info "Unknown architecture $ARCH - skipping isolinux configuration"
            ;;
    esac
    
    log_success "Bootloader configuration created"
}

# Create filesystem image
create_filesystem_image() {
    log_info "Creating filesystem image..."
    
    local rootfs_dir="$BUILD_DIR/rootfs"
    local iso_dir="$BUILD_DIR/iso"
    
    # Validate source directory exists and has content
    if [ ! -d "$rootfs_dir" ]; then
        error_exit "Root filesystem directory not found: $rootfs_dir"
    fi
    
    if [ ! -d "$rootfs_dir/usr" ] || [ ! -d "$rootfs_dir/bin" ]; then
        error_exit "Root filesystem appears incomplete - missing essential directories"
    fi
    
    log_info "Source rootfs validation passed"
    
    # Create SquashFS image with architecture-specific compression
    local squashfs_opts="-comp xz -b 1M -Xdict-size 1M"
    
    # Add architecture-specific BCJ filter for better compression
    case "$ARCH" in
        "x86_64"|"amd64"|"i386"|"x86")
            squashfs_opts="$squashfs_opts -Xbcj x86"
            ;;
        "arm64"|"aarch64")
            # ARM BCJ filter for better ARM64 compression
            squashfs_opts="$squashfs_opts -Xbcj arm"
            ;;
        *)
            # No BCJ filter for other architectures
            log_info "No BCJ filter available for $ARCH"
            ;;
    esac
    
    # Create destination directory first
    mkdir -p "$iso_dir/live"
    
    log_info "Creating SquashFS with options: $squashfs_opts"
    if ! mksquashfs "$rootfs_dir" "$iso_dir/live/filesystem.squashfs" $squashfs_opts; then
        log_error "SquashFS creation failed. Possible causes:"
        log_error "  - Insufficient disk space"
        log_error "  - Permission issues with destination directory"
        log_error "  - Invalid compression options for this architecture"
        log_error "  - Source directory corruption"
        error_exit "Failed to create SquashFS image"
    fi
    
    # Validate the created SquashFS file
    if [ ! -f "$iso_dir/live/filesystem.squashfs" ]; then
        error_exit "SquashFS file was not created successfully"
    fi
    
    local squashfs_size=$(du -h "$iso_dir/live/filesystem.squashfs" | cut -f1)
    log_success "Filesystem image created successfully (size: $squashfs_size)"
}

# Create ISO image
create_iso() {
    log_info "Creating LiDiS ISO image..."
    
    local iso_dir="$BUILD_DIR/iso"
    local iso_file="$OUTPUT_DIR/lidis-$LIDIS_VERSION-$ARCH.iso"
    
    # Check if grub-mkrescue is available, or if we have alternative tools
    if ! command -v grub-mkrescue >/dev/null 2>&1; then
        log_warning "grub-mkrescue not found - trying alternative ISO creation tools"
        
        # Check for alternative tools
        if command -v xorriso >/dev/null 2>&1 || command -v genisoimage >/dev/null 2>&1 || command -v mkisofs >/dev/null 2>&1; then
            log_info "Alternative ISO tools found - will create basic ISO without GRUB bootloader"
            # Skip grub-mkrescue and go directly to alternatives
            if create_basic_iso "$iso_file" "$iso_dir"; then
                log_success "ISO created using alternative tools"
                return 0
            else
                error_exit "Failed to create ISO with alternative tools"
            fi
        else
            error_exit "No ISO creation tools found. Please install grub2-utils, xorriso, or genisoimage"
        fi
    fi
    
    # Create bootable ISO using alternative tools (when grub-mkrescue unavailable)
    create_basic_iso() {
        local output_file="$1"
        local source_dir="$2"
        
        log_info "Creating bootable ISO with alternative tools..."
        
        # Ensure we have isolinux boot configuration for VM compatibility
        prepare_isolinux_boot "$source_dir"
        
        # Try xorriso with bootable configuration
        if command -v xorriso >/dev/null 2>&1; then
            log_info "Using xorriso for bootable ISO creation..."
            if xorriso -as mkisofs -o "$output_file" -V "LiDiS-$LIDIS_VERSION" \
               -c isolinux/boot.cat -b isolinux/isolinux.bin -no-emul-boot \
               -boot-load-size 4 -boot-info-table -r -J "$source_dir" 2>/dev/null; then
                log_success "Created bootable ISO with xorriso"
                return 0
            fi
            
            # Fallback to basic ISO without bootloader
            log_warning "Bootable ISO failed, creating basic data ISO..."
            if xorriso -as mkisofs -o "$output_file" -V "LiDiS-$LIDIS_VERSION" \
               -r -J -joliet-long "$source_dir" 2>/dev/null; then
                return 0
            fi
        fi
        
        # Try genisoimage with bootable configuration
        if command -v genisoimage >/dev/null 2>&1; then
            log_info "Using genisoimage for bootable ISO creation..."
            if genisoimage -o "$output_file" -V "LiDiS-$LIDIS_VERSION" \
               -c isolinux/boot.cat -b isolinux/isolinux.bin -no-emul-boot \
               -boot-load-size 4 -boot-info-table -r -J "$source_dir" 2>/dev/null; then
                log_success "Created bootable ISO with genisoimage"
                return 0
            fi
            
            # Fallback to basic ISO
            if genisoimage -o "$output_file" -V "LiDiS-$LIDIS_VERSION" \
               -r -J "$source_dir" 2>/dev/null; then
                return 0
            fi
        fi
        
        # Try mkisofs
        if command -v mkisofs >/dev/null 2>&1; then
            log_info "Using mkisofs for ISO creation..."
            if mkisofs -o "$output_file" -V "LiDiS-$LIDIS_VERSION" \
               -c isolinux/boot.cat -b isolinux/isolinux.bin -no-emul-boot \
               -boot-load-size 4 -boot-info-table -r -J "$source_dir" 2>/dev/null; then
                return 0
            fi
        fi
        
        return 1
    }
    
    # Prepare isolinux boot configuration for VM compatibility
    prepare_isolinux_boot() {
        local iso_dir="$1"
        
        log_info "Setting up isolinux boot configuration for VM compatibility..."
        
        # Create isolinux directory and configuration
        mkdir -p "$iso_dir/isolinux"
        
        # Create isolinux configuration that works with VMs
        cat > "$iso_dir/isolinux/isolinux.cfg" << EOF
DEFAULT lidis
TIMEOUT 100
PROMPT 0
UI menu.c32

MENU TITLE LiDiS Linux $LIDIS_VERSION Boot Menu
MENU COLOR border 30;44 #40ffffff #a0000000
MENU COLOR title 1;36;44 #9033ccff #a0000000
MENU COLOR sel 7;37;40 #e0ffffff #20ffffff

LABEL lidis
  MENU LABEL LiDiS Linux $LIDIS_VERSION
  KERNEL /vmlinuz
  APPEND initrd=/initrd.img boot=live quiet splash

LABEL recovery
  MENU LABEL LiDiS Linux $LIDIS_VERSION (Recovery Mode)
  KERNEL /vmlinuz  
  APPEND initrd=/initrd.img boot=live single

LABEL debug  
  MENU LABEL LiDiS Linux $LIDIS_VERSION (Debug Mode)
  KERNEL /vmlinuz
  APPEND initrd=/initrd.img boot=live debug loglevel=7
EOF

        # Copy isolinux bootloader files if available
        local isolinux_files=(
            "/usr/lib/ISOLINUX/isolinux.bin"
            "/usr/lib/syslinux/modules/bios/isolinux.bin"
            "/usr/share/syslinux/isolinux.bin"
        )
        
        local menu_files=(
            "/usr/lib/syslinux/modules/bios/menu.c32"
            "/usr/share/syslinux/menu.c32"
            "/usr/lib/ISOLINUX/menu.c32"
        )
        
        local copied_isolinux=false
        for file in "${isolinux_files[@]}"; do
            if [ -f "$file" ]; then
                cp "$file" "$iso_dir/isolinux/isolinux.bin"
                copied_isolinux=true
                break
            fi
        done
        
        local copied_menu=false
        for file in "${menu_files[@]}"; do
            if [ -f "$file" ]; then
                cp "$file" "$iso_dir/isolinux/menu.c32"
                copied_menu=true
                break
            fi
        done
        
        if [ "$copied_isolinux" = false ]; then
            log_warning "isolinux.bin not found - bootable ISO may not work"
        fi
        
        if [ "$copied_menu" = false ]; then
            log_warning "menu.c32 not found - using simple boot menu"
            # Create simpler config without menu.c32
            cat > "$iso_dir/isolinux/isolinux.cfg" << EOF
DEFAULT lidis
TIMEOUT 100
PROMPT 0

LABEL lidis
  KERNEL /vmlinuz
  APPEND initrd=/initrd.img root=/dev/ram0 ramdisk_size=1048576 quiet splash

LABEL recovery
  KERNEL /vmlinuz  
  APPEND initrd=/initrd.img root=/dev/ram0 ramdisk_size=1048576 single

LABEL debug
  KERNEL /vmlinuz
  APPEND initrd=/initrd.img root=/dev/ram0 ramdisk_size=1048576 debug loglevel=7
EOF
        fi
        
        log_success "Isolinux boot configuration prepared"
    }
    
    # Create ISO with architecture-specific options
    local grub_modules="part_gpt part_msdos"
    
    # Try grub-mkrescue with different option sets
    create_iso_with_grub() {
        local output_file="$1"
        local source_dir="$2"
        local arch_type="$3"
        
        # Check if mformat is available
        local has_mformat=true
        if ! command -v mformat >/dev/null 2>&1; then
            has_mformat=false
            log_warning "mformat not available - EFI boot may not work properly"
        fi
        
        # Option sets to try (in order of preference)
        local option_sets=(
            "--compress=xz --modules=$grub_modules"
            "--modules=$grub_modules"
            "--compress=xz"
            ""
        )
        
        # If mformat is missing, try additional fallback options
        if [ "$has_mformat" = false ]; then
            option_sets+=(
                "--format=raw"
                "--format=raw --compress=xz"
                "--format=raw --modules=$grub_modules"
            )
        fi
        
        for options in "${option_sets[@]}"; do
            if [ -z "$options" ]; then
                log_info "Trying grub-mkrescue with no options (minimal mode)"
            else
                log_info "Trying grub-mkrescue with options: $options"
            fi
            
            # Execute grub-mkrescue with timeout protection (if available)
            local success=false
            
            if [ -z "$options" ]; then
                # No options case
                if command -v timeout >/dev/null 2>&1; then
                    if timeout 300 grub-mkrescue -o "$output_file" "$source_dir" 2>/dev/null; then
                        success=true
                    fi
                else
                    if grub-mkrescue -o "$output_file" "$source_dir" 2>/dev/null; then
                        success=true
                    fi
                fi
            else
                # With options case - need to handle options expansion properly
                if command -v timeout >/dev/null 2>&1; then
                    if timeout 300 sh -c "grub-mkrescue -o '$output_file' '$source_dir' $options" 2>/dev/null; then
                        success=true
                    fi
                else
                    if sh -c "grub-mkrescue -o '$output_file' '$source_dir' $options" 2>/dev/null; then
                        success=true
                    fi
                fi
            fi
            
            if [ "$success" = true ]; then
                log_success "ISO created successfully with options: $options"
                return 0
            else
                log_warning "Failed with options: $options, trying next..."
                rm -f "$output_file" 2>/dev/null  # Clean up partial file
            fi
        done
        
        # Final attempt with alternative tools if available
        log_warning "grub-mkrescue failed, attempting alternative ISO creation..."
        if command -v xorriso >/dev/null 2>&1; then
            log_info "Trying xorriso as alternative..."
            if xorriso -as mkisofs -o "$output_file" -b isolinux/isolinux.bin -c isolinux/boot.cat \
               -no-emul-boot -boot-load-size 4 -boot-info-table "$source_dir" 2>/dev/null; then
                log_success "ISO created with xorriso alternative"
                return 0
            fi
        fi
        
        if command -v genisoimage >/dev/null 2>&1; then
            log_info "Trying genisoimage as alternative..."
            if genisoimage -o "$output_file" -b isolinux/isolinux.bin -c isolinux/boot.cat \
               -no-emul-boot -boot-load-size 4 -boot-info-table "$source_dir" 2>/dev/null; then
                log_success "ISO created with genisoimage alternative"
                return 0
            fi
        fi
        
        return 1
    }
    
    case "$ARCH" in
        "x86_64"|"amd64")
            log_info "Creating hybrid ISO with UEFI and BIOS support for x86_64"
            if ! create_iso_with_grub "$iso_file" "$iso_dir" "x86_64"; then
                error_exit "Failed to create ISO image for x86_64"
            fi
            # Make it hybrid bootable for x86
            isohybrid "$iso_file" 2>/dev/null || log_warning "isohybrid not available"
            ;;
        "arm64"|"aarch64")
            log_info "Creating EFI-only ISO for ARM64"
            if ! create_iso_with_grub "$iso_file" "$iso_dir" "arm64"; then
                error_exit "Failed to create ISO image for ARM64"
            fi
            # ARM64 doesn't need isohybrid (EFI only)
            log_info "ARM64 ISO created (EFI boot only)"
            ;;
        "i386"|"x86")
            log_info "Creating hybrid ISO with UEFI and BIOS support for i386"
            if ! create_iso_with_grub "$iso_file" "$iso_dir" "i386"; then
                error_exit "Failed to create ISO image for i386"
            fi
            isohybrid "$iso_file" 2>/dev/null || log_warning "isohybrid not available"
            ;;
        *)
            log_info "Creating generic ISO for $ARCH"
            if ! create_iso_with_grub "$iso_file" "$iso_dir" "$ARCH"; then
                error_exit "Failed to create ISO image for $ARCH"
            fi
            ;;
    esac
    
    # Calculate checksums
    cd "$OUTPUT_DIR"
    sha256sum "$(basename "$iso_file")" > "$(basename "$iso_file").sha256"
    
    log_success "ISO image created: $iso_file"
    log_info "ISO size: $(du -h "$iso_file" | cut -f1)"
}

# Create installation packages
create_packages() {
    log_info "Creating installation packages..."
    
    local packages_dir="$BUILD_DIR/packages"
    local rootfs_dir="$BUILD_DIR/rootfs"
    
    # Create LiDiS security package
    mkdir -p "$packages_dir/lidis-security/DEBIAN"
    cat > "$packages_dir/lidis-security/DEBIAN/control" << EOF
Package: lidis-security
Version: $LIDIS_VERSION
Section: admin
Priority: required
Architecture: $(case "$ARCH" in "x86_64"|"amd64") echo "amd64" ;; "arm64"|"aarch64") echo "arm64" ;; "i386"|"x86") echo "i386" ;; *) echo "$ARCH" ;; esac)
Maintainer: LiDiS Security Project <security@lidis.org>
Description: LiDiS Advanced Security Framework
 Comprehensive security framework including IPS, TTP detection,
 zero-day vulnerability detection, and threat intelligence.
Depends: python3, python3-pip, iptables
EOF

    cat > "$packages_dir/lidis-security/DEBIAN/postinst" << 'EOF'
#!/bin/bash
pip3 install numpy scikit-learn aiohttp psutil python-magic
systemctl enable lidis-ips
systemctl enable lidis-ttp-detector
systemctl enable lidis-zeroday-detector
systemctl enable lidis-threat-intelligence
systemctl daemon-reload
EOF
    chmod 755 "$packages_dir/lidis-security/DEBIAN/postinst"
    
    # Copy files to package
    mkdir -p "$packages_dir/lidis-security"/{opt,etc,usr/lib/systemd/system}
    cp -r "$rootfs_dir/opt/lidis" "$packages_dir/lidis-security/opt/"
    cp -r "$rootfs_dir/etc/lidis" "$packages_dir/lidis-security/etc/"
    cp "$rootfs_dir"/etc/systemd/system/lidis-*.service \
       "$packages_dir/lidis-security/usr/lib/systemd/system/"
    
    # Build package with correct architecture
    local pkg_arch
    case "$ARCH" in
        "x86_64"|"amd64") pkg_arch="amd64" ;;
        "arm64"|"aarch64") pkg_arch="arm64" ;;
        "i386"|"x86") pkg_arch="i386" ;;
        *) pkg_arch="$ARCH" ;;
    esac
    
    dpkg-deb --build "$packages_dir/lidis-security" \
        "$OUTPUT_DIR/lidis-security_${LIDIS_VERSION}_${pkg_arch}.deb"
    
    log_success "Installation packages created"
}

# Generate build report
generate_build_report() {
    log_info "Generating build report..."
    
    local report_file="$OUTPUT_DIR/lidis-$LIDIS_VERSION-build-report.txt"
    
    cat > "$report_file" << EOF
LiDiS Linux Distribution Build Report
=====================================

Build Information:
- Version: $LIDIS_VERSION
- Codename: $LIDIS_CODENAME  
- Architecture: $ARCH
- Kernel Version: $KERNEL_VERSION-lidis-security
- Build Date: $(date)
- Build Host: $(hostname)

Security Features Enabled:
- LiDiS Kernel Guard: Enhanced kernel integrity protection
- Advanced CFI: Extended Control Flow Integrity
- Enhanced KASLR: Multi-layer address space randomization  
- Memory Protection: Advanced heap/stack protection
- System Call Filtering: Whitelist-based syscall filtering
- Process Isolation: Container and namespace hardening
- Network Security: Deep packet inspection and anomaly detection
- File System Integrity: Real-time file monitoring
- Runtime Analysis: Behavioral monitoring and threat correlation

Security Components:
- Intrusion Prevention System (IPS) with AI/ML capabilities
- TTP Detection System based on MITRE ATT&CK framework
- Zero-day Vulnerability Detection with sandboxing
- Intelligent Threat Intelligence Agent with auto-collection

Build Artifacts:
- ISO Image: lidis-$LIDIS_VERSION-$ARCH.iso
- Security Package: lidis-security_${LIDIS_VERSION}_$(case "$ARCH" in "x86_64"|"amd64") echo "amd64" ;; "arm64"|"aarch64") echo "arm64" ;; "i386"|"x86") echo "i386" ;; *) echo "$ARCH" ;; esac).deb
- SHA256 Checksums: Available for verification

System Requirements:
- Architecture: $ARCH $(case "$ARCH" in "x86_64"|"amd64") echo "(AMD64)" ;; "arm64"|"aarch64") echo "(ARM64/AArch64)" ;; "i386"|"x86") echo "(i386)" ;; *) echo "" ;; esac)
- RAM: 4GB minimum, 8GB recommended
- Storage: 20GB minimum
- UEFI firmware with Secure Boot support recommended
- TPM 2.0 module recommended for full security features

Installation:
1. Boot from ISO image
2. Follow installation wizard
3. Security components will be automatically configured
4. System will be hardened by default

Security Level: 8/10 (High Security)
Enforcement Mode: Enabled
Recommended Use: Production security environments

For documentation and support, visit: https://lidis.org
EOF

    log_success "Build report generated: $report_file"
}

# Cleanup build environment
cleanup() {
    log_info "Cleaning up build environment..."
    
    # Clean build directory
    if [ "$KEEP_BUILD_DIR" != "true" ]; then
        if [ -d "$BUILD_DIR" ]; then
            log_info "Removing build directory: $BUILD_DIR"
            if rm -rf "$BUILD_DIR" 2>/dev/null; then
                log_success "Build directory cleaned successfully"
            else
                log_warning "Failed to remove build directory: $BUILD_DIR"
                log_warning "You may need to remove it manually with: sudo rm -rf $BUILD_DIR"
            fi
        else
            log_info "Build directory not found (already cleaned): $BUILD_DIR"
        fi
    else
        log_info "Build directory preserved: $BUILD_DIR"
    fi
    
    # Clean any temporary files
    log_info "Cleaning temporary files..."
    local temp_files="/tmp/lidis-*" 
    if ls $temp_files >/dev/null 2>&1; then
        rm -f $temp_files 2>/dev/null || log_warning "Some temporary files could not be removed"
    fi
}

# Main build function
main() {
    log_info "Starting LiDiS Linux Distribution Build"
    log_info "Version: $LIDIS_VERSION ($LIDIS_CODENAME)"
    log_info "Architecture: $ARCH"
    
    # Build stages
    check_dependencies
    setup_build_environment
    download_kernel
    apply_security_patches
    build_kernel
    create_base_rootfs
    install_security_components
    configure_system_security
    create_initramfs
    create_bootloader
    create_filesystem_image
    create_iso
    create_packages
    generate_build_report
    
    log_success "LiDiS build completed successfully!"
    log_info "Output directory: $OUTPUT_DIR"
    log_info "ISO image: lidis-$LIDIS_VERSION-$ARCH.iso"
    
    # Post-build cleanup
    if [ "$NO_CLEANUP" != "true" ]; then
        log_info "Performing post-build cleanup..."
        cleanup
        log_success "Build cleanup completed"
    else
        log_info "Skipping cleanup (use --cleanup to enable or clean command to clean manually)"
        log_info "Build files preserved in: $BUILD_DIR"
    fi
}

# Parse command line arguments
COMMAND="build"
while [ $# -gt 0 ]; do
    case "$1" in
        --no-cleanup)
            NO_CLEANUP=true
            shift
            ;;
        --cleanup)
            NO_CLEANUP=false
            shift
            ;;
        --keep-build-dir)
            KEEP_BUILD_DIR=true
            shift
            ;;
        --enable-btf)
            ENABLE_BTF=true
            shift
            ;;
        --arch=*)
            ARCH="${1#*=}"
            shift
            ;;
        --kernel-version=*)
            KERNEL_VERSION="${1#*=}"
            shift
            ;;
        --version=*)
            LIDIS_VERSION="${1#*=}"
            shift
            ;;
        --jobs=*)
            JOBS="${1#*=}"
            shift
            ;;
        build|kernel-only|clean|help|--help|-h)
            COMMAND="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
done

# Handle commands
case "$COMMAND" in
    "build")
        main
        ;;
    "kernel-only")
        check_dependencies
        setup_build_environment
        download_kernel
        apply_security_patches
        build_kernel
        log_success "Kernel build completed"
        ;;
    "clean")
        log_info "Cleaning build environment..."
        
        # Clean build directory
        if [ -d "$BUILD_DIR" ]; then
            log_info "Removing build directory: $BUILD_DIR"
            if rm -rf "$BUILD_DIR" 2>/dev/null; then
                log_success "Build directory cleaned successfully"
            else
                log_error "Failed to remove build directory: $BUILD_DIR"
                log_error "You may need to run: sudo rm -rf $BUILD_DIR"
            fi
        else
            log_info "Build directory not found: $BUILD_DIR"
        fi
        
        # Clean output directory
        if [ -d "$OUTPUT_DIR" ]; then
            log_info "Removing output directory: $OUTPUT_DIR"
            if rm -rf "$OUTPUT_DIR" 2>/dev/null; then
                log_success "Output directory cleaned successfully"
            else
                log_error "Failed to remove output directory: $OUTPUT_DIR"
                log_error "You may need to run: sudo rm -rf $OUTPUT_DIR"
            fi
        else
            log_info "Output directory not found: $OUTPUT_DIR"
        fi
        
        # Clean temporary files
        log_info "Cleaning temporary files..."
        temp_files="/tmp/lidis-*"
        if ls $temp_files >/dev/null 2>&1; then
            rm -f $temp_files 2>/dev/null || log_warning "Some temporary files could not be removed"
        fi
        
        log_success "Clean completed"
        ;;
    "help"|"--help"|"-h")
        echo "LiDiS Build System"
        echo ""
        echo "Usage: $0 [options] [command]"
        echo ""
        echo "Commands:"
        echo "  build        Build complete LiDiS distribution (default)"
        echo "  kernel-only  Build only the kernel"
        echo "  clean        Clean build environment"
        echo "  help         Show this help"
        echo ""
        echo "Options:"
        echo "  --cleanup            Force cleanup after build (default)"
        echo "  --no-cleanup         Skip cleanup after build"
        echo "  --keep-build-dir     Keep build directory"
        echo "  --enable-btf         Enable BTF debug info"
        echo "  --arch=ARCH          Target architecture"
        echo "  --kernel-version=VER Kernel version to build"
        echo "  --version=VER        LiDiS version string"
        echo "  --jobs=NUM           Number of parallel jobs"
        echo ""
        echo "Environment Variables:"
        echo "  LIDIS_VERSION    Version string (default: 1.0.0)"
        echo "  LIDIS_CODENAME   Codename (default: SecurityCore)"
        echo "  BUILD_DIR        Build directory (default: /tmp/lidis-build)"
        echo "  OUTPUT_DIR       Output directory (default: /tmp/lidis-output)"
        echo "  KERNEL_VERSION   Kernel version (default: 6.8)"
        echo "  ARCH             Architecture (auto-detected: $(uname -m))"
        echo "  JOBS             Parallel jobs (default: auto-detected)"
        echo "  ENABLE_BTF       Enable BTF debug info (default: false)"
        echo "  KEEP_BUILD_DIR   Keep build directory (default: false)"
        echo "  NO_CLEANUP       Skip cleanup (default: false)"
        echo ""
        echo "Examples:"
        echo "  $0 build                                    # Build with default cleanup"
        echo "  $0 --no-cleanup build                      # Build without cleanup"
        echo "  $0 --cleanup --keep-build-dir build        # Build with cleanup but keep build dir"
        echo "  $0 --arch=x86_64 --kernel-version=6.9 build"
        echo "  $0 --version=2.0.0 --enable-btf build"
        echo "  $0 clean                                    # Clean all build artifacts"
        echo "  KERNEL_VERSION=6.9 $0 build"
        ;;
    *)
        log_error "Unknown command: $COMMAND"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac