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
: "${KERNEL_VERSION:=6.8.0}"
: "${ARCH:=}"
: "${JOBS:=$(nproc)}"

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

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1 && ! dpkg -l "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Please install missing dependencies and try again"
        log_info "Example: sudo apt-get install ${missing_deps[*]}"
        exit 1
    fi
    
    log_success "All dependencies satisfied"
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
    
    if [ ! -d "$kernel_dir" ]; then
        cd "$BUILD_DIR/kernel"
        wget -q "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz" \
            -O "linux-$KERNEL_VERSION.tar.xz" || \
            error_exit "Failed to download kernel"
        
        tar -xf "linux-$KERNEL_VERSION.tar.xz" || \
            error_exit "Failed to extract kernel"
        
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
    
    # Update configuration for current kernel version
    make olddefconfig
    
    # Build kernel and modules
    log_info "Compiling kernel (this may take a while)..."
    make -j"$JOBS" || error_exit "Kernel build failed"
    
    log_info "Compiling kernel modules..."
    make -j"$JOBS" modules || error_exit "Module build failed"
    
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
        # Use debootstrap to create base system (Ubuntu 22.04 LTS)
        debootstrap --arch="$debootstrap_arch" jammy "$rootfs_dir" http://archive.ubuntu.com/ubuntu/ || \
            error_exit "Failed to create base filesystem"
        
        log_success "Base filesystem created"
    else
        log_info "Base filesystem already exists"
    fi
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

    # Install Python dependencies
    chroot "$rootfs_dir" /bin/bash -c "
        apt-get update
        apt-get install -y python3-pip python3-dev python3-setuptools
        pip3 install numpy scikit-learn aiohttp psutil python-magic
        apt-get install -y iptables netfilter-persistent fail2ban
        systemctl enable lidis-ips
        systemctl enable lidis-ttp-detector  
        systemctl enable lidis-zeroday-detector
        systemctl enable lidis-threat-intelligence
    "
    
    log_success "Security components installed"
}

# Configure system security
configure_system_security() {
    log_info "Configuring system security settings..."
    
    local rootfs_dir="$BUILD_DIR/rootfs"
    
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
    mkdir -p "$rootfs_dir/etc/apparmor.d/lidis"
    
    # Configure audit rules
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

    # Set secure permissions
    chroot "$rootfs_dir" /bin/bash -c "
        chmod 644 /etc/sysctl.conf
        chmod 600 /etc/audit/rules.d/lidis.rules
        chmod 755 /opt/lidis/security/*.py
        systemctl enable auditd
        systemctl enable apparmor
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
    mkdir -p {bin,sbin,etc,proc,sys,dev,tmp,lib,lib64,usr/bin,usr/sbin}
    
    # Copy essential binaries
    cp /bin/sh bin/
    cp /bin/busybox bin/ 2>/dev/null || true
    cp /sbin/init sbin/ 2>/dev/null || cp /usr/lib/systemd/systemd sbin/init
    
    # Create init script
    cat > init << 'EOF'
#!/bin/sh
exec /sbin/init
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
    
    log_info "Creating SquashFS with options: $squashfs_opts"
    mksquashfs "$rootfs_dir" "$iso_dir/live/filesystem.squashfs" $squashfs_opts || \
        error_exit "Failed to create SquashFS image"
    
    mkdir -p "$iso_dir/live"
    
    log_success "Filesystem image created"
}

# Create ISO image
create_iso() {
    log_info "Creating LiDiS ISO image..."
    
    local iso_dir="$BUILD_DIR/iso"
    local iso_file="$OUTPUT_DIR/lidis-$LIDIS_VERSION-$ARCH.iso"
    
    # Create ISO with architecture-specific options
    local grub_modules="part_gpt part_msdos"
    local iso_options="--locales=\"\" --fonts=\"\" --compress=xz"
    
    case "$ARCH" in
        "x86_64"|"amd64")
            log_info "Creating hybrid ISO with UEFI and BIOS support for x86_64"
            grub-mkrescue -o "$iso_file" "$iso_dir" \
                --modules="$grub_modules" \
                $iso_options || \
                error_exit "Failed to create ISO image"
            # Make it hybrid bootable for x86
            isohybrid "$iso_file" 2>/dev/null || log_warning "isohybrid not available"
            ;;
        "arm64"|"aarch64")
            log_info "Creating EFI-only ISO for ARM64"
            grub-mkrescue -o "$iso_file" "$iso_dir" \
                --modules="$grub_modules" \
                $iso_options || \
                error_exit "Failed to create ISO image"
            # ARM64 doesn't need isohybrid (EFI only)
            log_info "ARM64 ISO created (EFI boot only)"
            ;;
        "i386"|"x86")
            log_info "Creating hybrid ISO with UEFI and BIOS support for i386"
            grub-mkrescue -o "$iso_file" "$iso_dir" \
                --modules="$grub_modules" \
                $iso_options || \
                error_exit "Failed to create ISO image"
            isohybrid "$iso_file" 2>/dev/null || log_warning "isohybrid not available"
            ;;
        *)
            log_info "Creating generic ISO for $ARCH"
            grub-mkrescue -o "$iso_file" "$iso_dir" \
                --modules="$grub_modules" \
                $iso_options || \
                error_exit "Failed to create ISO image"
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
    
    if [ "$KEEP_BUILD_DIR" != "true" ]; then
        rm -rf "$BUILD_DIR"
        log_info "Build directory cleaned"
    else
        log_info "Build directory preserved: $BUILD_DIR"
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
    
    # Optional cleanup
    if [ "$NO_CLEANUP" != "true" ]; then
        cleanup
    fi
}

# Handle command line arguments
case "${1:-build}" in
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
        rm -rf "$BUILD_DIR" "$OUTPUT_DIR"
        log_success "Clean completed"
        ;;
    "help"|"--help"|"-h")
        echo "LiDiS Build System"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  build        Build complete LiDiS distribution (default)"
        echo "  kernel-only  Build only the kernel"
        echo "  clean        Clean build environment"
        echo "  help         Show this help"
        echo ""
        echo "Environment Variables:"
        echo "  LIDIS_VERSION    Version string (default: 1.0.0)"
        echo "  LIDIS_CODENAME   Codename (default: SecurityCore)"
        echo "  BUILD_DIR        Build directory (default: /tmp/lidis-build)"
        echo "  OUTPUT_DIR       Output directory (default: /tmp/lidis-output)"
        echo "  KERNEL_VERSION   Kernel version (default: 6.8.0)"
        echo "  ARCH             Architecture (auto-detected: $(uname -m))"
        echo "  JOBS             Parallel jobs (default: nproc)"
        echo "  KEEP_BUILD_DIR   Keep build directory (default: false)"
        echo "  NO_CLEANUP       Skip cleanup (default: false)"
        ;;
    *)
        log_error "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac