#!/bin/bash
#
# Quick fix for Ubuntu package naming issues
# Specifically addresses syslinux-utils, grub-efi-amd64-bin, grub-pc-bin issues
#

set -euo pipefail

echo "🔧 LiDiS Ubuntu Package Fix"
echo "==========================="

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

# Fix GRUB EFI packages
echo ""
echo "2. Fixing GRUB EFI packages..."
install_with_alternatives "grub-efi" \
    "grub-efi-amd64-bin" \
    "grub-efi-amd64" \
    "grub-efi" \
    "grub2-efi-amd64-modules" \
    "grub-efi-ia32-bin"

# Fix GRUB PC packages  
echo ""
echo "3. Fixing GRUB PC packages..."
install_with_alternatives "grub-pc" \
    "grub-pc-bin" \
    "grub-pc" \
    "grub2-pc-modules" \
    "grub-legacy"

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

# Test critical commands
test_commands=(
    "syslinux"
    "isolinux" 
    "grub-install"
    "grub-mkrescue"
    "genisoimage"
    "mksquashfs"
    "debootstrap"
)

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
    echo "Manual installation may be required for:"
    for cmd in "${missing_commands[@]}"; do
        case "$cmd" in
            "syslinux"|"isolinux")
                echo "   - For bootloader: sudo apt-get install syslinux-common isolinux"
                ;;
            "grub-install"|"grub-mkrescue")
                echo "   - For GRUB: sudo apt-get install grub-common grub2-common"
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
echo "📋 Package Status Summary:"
echo "=========================="
dpkg -l | grep -E "(syslinux|grub|genisoimage|squashfs|debootstrap)" | head -10