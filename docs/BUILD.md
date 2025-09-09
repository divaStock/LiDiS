# LiDiS Build Guide

This guide explains how to build LiDiS Linux distribution from source.

## System Requirements

### Build Host Requirements
- Ubuntu 20.04 LTS or later (or compatible Debian-based system)
- Minimum 8GB RAM (16GB recommended for faster builds)
- 50GB free disk space
- Internet connection for downloading components

### Build Dependencies
The build system will automatically check for and install these dependencies:

#### Essential Build Tools
- gcc, make, git
- wget, curl
- flex, bison
- bc, kmod, cpio, rsync

#### Kernel Build Dependencies
- libssl-dev
- libelf-dev
- python3, python3-pip

#### Distribution Build Tools
- debootstrap
- squashfs-tools
- genisoimage
- isolinux, syslinux-utils
- grub-efi-amd64-bin, grub-pc-bin
- mtools, dosfstools, parted

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/lidis-project/LiDiS.git
   cd LiDiS
   ```

2. **Install dependencies:**
   ```bash
   sudo apt update
   sudo apt install build-essential git wget curl debootstrap squashfs-tools \
                    genisoimage isolinux syslinux-utils grub-efi-amd64-bin \
                    grub-pc-bin mtools dosfstools parted python3 python3-pip \
                    flex bison libssl-dev libelf-dev bc kmod cpio rsync
   ```

3. **Build LiDiS:**
   ```bash
   ./scripts/build_lidis.sh
   ```

The build process will take 1-3 hours depending on your system performance.

## Build Configuration

### Environment Variables

You can customize the build by setting environment variables:

```bash
export LIDIS_VERSION="1.0.1"
export LIDIS_CODENAME="SecureCore"
export BUILD_DIR="/opt/lidis-build"
export OUTPUT_DIR="/opt/lidis-output"
export KERNEL_VERSION="6.8.0"
export ARCH="x86_64"
export JOBS="8"
```

### Build Commands

#### Full Build (Default)
```bash
./scripts/build_lidis.sh build
```

#### Kernel Only Build
```bash
./scripts/build_lidis.sh kernel-only
```

#### Clean Build Environment
```bash
./scripts/build_lidis.sh clean
```

## Build Process Overview

The build system performs the following stages:

### 1. Dependency Check
- Verifies all required build tools are installed
- Provides installation instructions for missing dependencies

### 2. Environment Setup
- Creates build directory structure
- Sets up environment variables
- Prepares workspace

### 3. Kernel Build
- Downloads Linux kernel source (6.8.0 by default)
- Applies LiDiS security patches
- Configures kernel with hardened security settings
- Compiles kernel with security enhancements
- Builds kernel modules

### 4. Root Filesystem Creation
- Creates base Ubuntu 22.04 LTS filesystem using debootstrap
- Installs essential system packages
- Configures system security settings

### 5. Security Components Installation
- Installs LiDiS security framework
- Configures IPS, TTP detection, zero-day detection systems
- Sets up threat intelligence agent
- Creates systemd service files
- Installs Python dependencies

### 6. System Hardening
- Applies kernel security parameters
- Configures AppArmor profiles
- Sets up audit rules
- Hardens network and filesystem settings

### 7. Boot System Creation
- Creates initramfs
- Configures GRUB and isolinux bootloaders
- Sets up UEFI and BIOS boot support

### 8. Image Generation
- Creates compressed SquashFS filesystem
- Generates hybrid ISO image with dual boot support
- Calculates checksums for verification

### 9. Package Creation
- Creates installable .deb packages
- Generates build report
- Prepares distribution artifacts

## Security Features

The built LiDiS distribution includes:

### Kernel-Level Security
- **Enhanced CFI**: Extended Control Flow Integrity
- **Advanced KASLR**: Multi-layer address randomization
- **Kernel Guard**: Runtime kernel integrity protection
- **Memory Protection**: Heap/stack overflow protection
- **Hardware Integration**: TPM 2.0, Intel CET, ARM features

### Security Applications
- **IPS Engine**: AI-powered intrusion prevention
- **TTP Detector**: MITRE ATT&CK framework-based detection
- **Zero-day Scanner**: Vulnerability discovery and sandboxing
- **Threat Intelligence**: Automated intelligence gathering

### System Hardening
- SELinux/AppArmor mandatory access control
- Comprehensive audit logging
- Network security hardening
- Filesystem integrity monitoring

## Build Outputs

After successful build, you'll find these artifacts in the output directory:

- `lidis-[version]-[arch].iso` - Bootable ISO image
- `lidis-[version]-[arch].iso.sha256` - Checksum file
- `lidis-security_[version]_amd64.deb` - Security package
- `lidis-[version]-build-report.txt` - Detailed build report

## Customization

### Adding Custom Packages
Edit the `create_base_rootfs()` function in `build_lidis.sh` to install additional packages:

```bash
chroot "$rootfs_dir" /bin/bash -c "
    apt-get update
    apt-get install -y your-custom-package
"
```

### Modifying Kernel Configuration
1. Edit `configs/kernel_config` to change kernel options
2. Add custom patches to `patches/kernel/` directory
3. Rebuild with `./scripts/build_lidis.sh kernel-only`

### Custom Security Policies
1. Add AppArmor profiles to appropriate directories
2. Modify audit rules in the configuration section
3. Add custom security modules to `src/security/`

## Troubleshooting

### Common Build Issues

**Out of disk space:**
- Ensure at least 50GB free space
- Use `KEEP_BUILD_DIR=false` to auto-cleanup

**Missing dependencies:**
- Run the dependency check manually
- Install missing packages as suggested

**Kernel build failures:**
- Check kernel configuration compatibility
- Verify patch compatibility with kernel version
- Review build logs for specific errors

**Permission errors:**
- Ensure user has sudo access for chroot operations
- Check file permissions on build directories

### Debug Mode
Enable verbose logging:
```bash
DEBUG=1 ./scripts/build_lidis.sh
```

### Build Logs
Build logs are available in:
- `$BUILD_DIR/build.log` - Main build log
- `$BUILD_DIR/kernel/build.log` - Kernel build log

## Performance Tips

### Faster Builds
1. **Use more CPU cores:** `export JOBS=$(nproc)`
2. **Use SSD storage:** Build on SSD for better I/O performance
3. **More RAM:** 16GB+ RAM speeds up compilation significantly
4. **ccache:** Install ccache for faster kernel rebuilds

### Parallel Building
The build system supports parallel execution where possible:
- Kernel compilation uses all available cores
- Module building is parallelized
- Some stages run concurrently when safe

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Build LiDiS
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Install dependencies
      run: |
        sudo apt update
        sudo apt install -y build-essential debootstrap squashfs-tools ...
    - name: Build LiDiS
      run: ./scripts/build_lidis.sh
    - name: Upload artifacts
      uses: actions/upload-artifact@v2
      with:
        name: lidis-iso
        path: /tmp/lidis-output/*.iso
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh './scripts/build_lidis.sh'
            }
        }
        stage('Test') {
            steps {
                sh './scripts/test_lidis.sh'
            }
        }
        stage('Archive') {
            steps {
                archiveArtifacts artifacts: '/tmp/lidis-output/*'
            }
        }
    }
}
```

## Next Steps

After successful build:
1. Test the ISO in a virtual machine
2. Review the security configuration
3. Customize for your environment
4. Deploy to production systems

For installation instructions, see [INSTALL.md](INSTALL.md).
For security configuration, see [SECURITY.md](SECURITY.md).