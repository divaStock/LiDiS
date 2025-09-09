#!/bin/bash
#
# Quick fix for Ubuntu package naming issues
# Supports AMD64, ARM64, and other architectures
# Specifically addresses syslinux-utils, grub-efi-*-bin, grub-pc-bin issues
#

set -euo pipefail

echo "🔧 LiDiS Ubuntu Package Fix"
echo "==========================="

# Detect architecture
ARCH=$(dpkg --print-architecture)
echo "🏗️  Detected architecture: $ARCH"

# Update package cache
echo "📦 Updating package cache..."
sudo apt-get update

# Function to try installing packages with alternatives
install_with_alternatives() {
    local package_name="$1"
    shift
    local alternatives=("$@")
    
    echo "🔍 Installing $package_name..."
    
    # Try each alternative until one works
    for alt in "${alternatives[@]}"; do
        if apt-cache show "$alt" >/dev/null 2>&1; then
            echo "   Found $alt, installing..."
            if sudo apt-get install -y "$alt"; then
                echo "   ✅ Successfully installed $alt"
                return 0
            else
                echo "   ❌ Failed to install $alt"
            fi
        else
            echo "   ⚠️  Package $alt not available"
        fi
    done
    
    echo "   ❌ Could not install $package_name with any alternative"
    return 1
}

echo ""
echo "🛠️  Fixing specific package issues..."

# Fix syslinux-utils
echo "1. Fixing syslinux packages..."
install_with_alternatives "syslinux" \
    "syslinux-utils" \
    "syslinux-common" \
    "syslinux" \
    "isolinux"

# Fix GRUB EFI packages (architecture-specific)
echo ""
echo "2. Fixing GRUB EFI packages for $ARCH..."

case "$ARCH" in
    "amd64"|"x86_64")
        echo "   Installing AMD64/x86_64 GRUB EFI packages..."
        install_with_alternatives "grub-efi-amd64" \
            "grub-efi-amd64-bin" \
            "grub-efi-amd64" \
            "grub-efi" \
            "grub2-efi-amd64-modules" \
            "grub-efi-amd64-signed"
        ;;
    "arm64"|"aarch64")
        echo "   Installing ARM64/AArch64 GRUB EFI packages..."
        install_with_alternatives "grub-efi-arm64" \
            "grub-efi-arm64-bin" \
            "grub-efi-arm64" \
            "grub-efi" \
            "grub2-efi-arm64-modules" \
            "grub-efi-arm64-signed"
        ;;
    "i386"|"x86")
        echo "   Installing i386/x86 GRUB EFI packages..."
        install_with_alternatives "grub-efi-ia32" \
            "grub-efi-ia32-bin" \
            "grub-efi-ia32" \
            "grub-efi" \
            "grub2-efi-ia32-modules"
        ;;
    *)
        echo "   Installing generic GRUB EFI packages for $ARCH..."
        install_with_alternatives "grub-efi" \
            "grub-efi" \
            "grub-common" \
            "grub2-common"
        ;;
esac

# Fix GRUB PC packages (x86/AMD64 only - ARM64 uses EFI only)
echo ""
case "$ARCH" in
    "amd64"|"x86_64"|"i386"|"x86")
        echo "3. Fixing GRUB PC packages for $ARCH..."
        install_with_alternatives "grub-pc" \
            "grub-pc-bin" \
            "grub-pc" \
            "grub2-pc-modules" \
            "grub-legacy"
        ;;
    "arm64"|"aarch64")
        echo "3. Skipping GRUB PC packages (ARM64 uses EFI only)..."
        echo "   ✅ ARM64 systems use EFI boot only - no PC/BIOS packages needed"
        ;;
    *)
        echo "3. Installing generic GRUB packages for $ARCH..."
        install_with_alternatives "grub-common" \
            "grub-common" \
            "grub2-common"
        ;;
esac

# Additional essential packages that might be missing
echo ""
echo "4. Installing additional essential packages..."

additional_packages=(
    "genisoimage"
    "xorriso"
    "mtools" 
    "dosfstools"
    "squashfs-tools"
    "debootstrap"
)

for pkg in "${additional_packages[@]}"; do
    if ! dpkg -l "$pkg" >/dev/null 2>&1; then
        if apt-cache show "$pkg" >/dev/null 2>&1; then
            echo "   Installing $pkg..."
            sudo apt-get install -y "$pkg" || echo "   Failed to install $pkg"
        fi
    else
        echo "   ✅ $pkg already installed"
    fi
done

echo ""
echo "🧪 Testing installations..."

# Test critical commands (architecture-specific)
test_commands=()

# Add common commands for all architectures
test_commands+=(
    "genisoimage"
    "mksquashfs"
    "debootstrap"
    "grub-install"
    "grub-mkrescue"
)

# Add architecture-specific commands
case "$ARCH" in
    "amd64"|"x86_64"|"i386"|"x86")
        test_commands+=(
            "syslinux"
            "isolinux"
        )
        echo "   Testing x86/AMD64 specific tools..."
        ;;
    "arm64"|"aarch64")
        # ARM64 doesn't typically use syslinux/isolinux
        echo "   Testing ARM64 specific tools (EFI only)..."
        ;;
    *)
        echo "   Testing generic tools for $ARCH..."
        ;;
esac

missing_commands=()
for cmd in "${test_commands[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "   ✅ $cmd available"
    else
        echo "   ❌ $cmd missing"
        missing_commands+=("$cmd")
    fi
done

echo ""
if [ ${#missing_commands[@]} -eq 0 ]; then
    echo "🎉 All package fixes completed successfully!"
    echo ""
    echo "You can now run the LiDiS build:"
    echo "   ./scripts/build_lidis.sh"
else
    echo "⚠️  Some commands are still missing: ${missing_commands[*]}"
    echo ""
    echo "Manual installation may be required for $ARCH:"
    for cmd in "${missing_commands[@]}"; do
        case "$cmd" in
            "syslinux"|"isolinux")
                if [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
                    echo "   - Note: $cmd not needed on ARM64 (EFI boot only)"
                else
                    echo "   - For bootloader: sudo apt-get install syslinux-common isolinux"
                fi
                ;;
            "grub-install"|"grub-mkrescue")
                case "$ARCH" in
                    "amd64"|"x86_64")
                        echo "   - For GRUB (AMD64): sudo apt-get install grub-common grub-efi-amd64"
                        ;;
                    "arm64"|"aarch64")
                        echo "   - For GRUB (ARM64): sudo apt-get install grub-common grub-efi-arm64"
                        ;;
                    "i386"|"x86")
                        echo "   - For GRUB (i386): sudo apt-get install grub-common grub-efi-ia32"
                        ;;
                    *)
                        echo "   - For GRUB: sudo apt-get install grub-common grub2-common"
                        ;;
                esac
                ;;
            "genisoimage")
                echo "   - For ISO creation: sudo apt-get install genisoimage or xorriso"
                ;;
            "mksquashfs")
                echo "   - For filesystem: sudo apt-get install squashfs-tools"
                ;;
            "debootstrap")
                echo "   - For base system: sudo apt-get install debootstrap"
                ;;
        esac
    done
fi

echo ""
echo "📋 Package Status Summary for $ARCH:"
echo "===================================="
echo "🏗️  Architecture: $ARCH"
case "$ARCH" in
    "amd64"|"x86_64")
        echo "✅ Supports: GRUB EFI (amd64), GRUB PC (BIOS), SYSLINUX"
        echo "📦 Boot options: EFI + BIOS legacy boot"
        ;;
    "arm64"|"aarch64")
        echo "✅ Supports: GRUB EFI (arm64) only"
        echo "📦 Boot options: EFI only (no BIOS/SYSLINUX needed)"
        echo "⚠️  Note: ARM64 uses EFI boot exclusively"
        ;;
    "i386"|"x86")
        echo "✅ Supports: GRUB EFI (ia32), GRUB PC (BIOS), SYSLINUX"
        echo "📦 Boot options: EFI + BIOS legacy boot"
        ;;
    *)
        echo "✅ Supports: Generic GRUB packages"
        echo "📦 Boot options: Architecture-dependent"
        ;;
esac
echo ""
dpkg -l | grep -E "(syslinux|grub|genisoimage|squashfs|debootstrap)" | head -10