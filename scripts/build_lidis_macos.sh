#!/bin/bash
#
# LiDiS Build Script for macOS
# Uses Docker to handle Linux-specific build requirements
#

set -euo pipefail

# Configuration
LIDIS_VERSION="${LIDIS_VERSION:-1.0.0}"
DOCKER_IMAGE="lidis-builder"
WORK_DIR="$(pwd)"
BUILD_DIR="${BUILD_DIR:-$HOME/lidis-build}"
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/lidis-output}"

# Colors
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

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker is not running. Please start Docker Desktop and try again."
        exit 1
    fi
    log_success "Docker is running"
}

# Create Docker build image
create_build_image() {
    log_info "Creating Docker build environment..."
    
    cat > Dockerfile.lidis << 'EOF'
FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    wget \
    curl \
    debootstrap \
    squashfs-tools \
    genisoimage \
    isolinux \
    syslinux-utils \
    grub-efi-amd64-bin \
    grub-pc-bin \
    mtools \
    dosfstools \
    parted \
    python3 \
    python3-pip \
    flex \
    bison \
    libssl-dev \
    libelf-dev \
    bc \
    kmod \
    cpio \
    rsync \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create build user
RUN useradd -m -s /bin/bash builder && \
    echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

WORKDIR /workspace
USER builder
EOF

    docker build -f Dockerfile.lidis -t "$DOCKER_IMAGE" . || {
        log_error "Failed to build Docker image"
        exit 1
    }
    
    # Cleanup
    rm Dockerfile.lidis
    
    log_success "Docker build environment ready"
}

# Run build in Docker container
run_docker_build() {
    log_info "Starting LiDiS build in Docker container..."
    
    # Create output directory on host
    mkdir -p "$OUTPUT_DIR"
    
    # Run the build
    docker run --rm -it \
        --privileged \
        -v "$WORK_DIR:/workspace" \
        -v "$OUTPUT_DIR:/output" \
        -e LIDIS_VERSION="$LIDIS_VERSION" \
        -e BUILD_DIR="/tmp/lidis-build" \
        -e OUTPUT_DIR="/output" \
        "$DOCKER_IMAGE" \
        bash -c "
            cd /workspace
            sudo ./scripts/build_lidis.sh
        "
    
    if [ $? -eq 0 ]; then
        log_success "Build completed successfully!"
        log_info "Output files are in: $OUTPUT_DIR"
    else
        log_error "Build failed"
        exit 1
    fi
}

# Main function
main() {
    log_info "LiDiS macOS Build System"
    log_info "Version: $LIDIS_VERSION"
    
    check_docker
    create_build_image
    run_docker_build
    
    log_success "LiDiS build process completed"
    echo ""
    echo "Next steps:"
    echo "1. Test the ISO: $OUTPUT_DIR/lidis-$LIDIS_VERSION-x86_64.iso"
    echo "2. Deploy to a Linux VM or physical machine"
    echo "3. Boot from the ISO to run LiDiS"
}

# Handle arguments
case "${1:-build}" in
    "build")
        main
        ;;
    "clean")
        log_info "Cleaning up Docker images..."
        docker rmi "$DOCKER_IMAGE" 2>/dev/null || true
        rm -rf "$BUILD_DIR" "$OUTPUT_DIR"
        log_success "Cleanup completed"
        ;;
    "shell")
        log_info "Starting Docker shell for debugging..."
        docker run --rm -it \
            --privileged \
            -v "$WORK_DIR:/workspace" \
            "$DOCKER_IMAGE" \
            bash
        ;;
    "help"|"--help"|"-h")
        echo "LiDiS macOS Build System"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  build        Build LiDiS distribution (default)"
        echo "  clean        Clean Docker images and build directories"
        echo "  shell        Start Docker shell for debugging"
        echo "  help         Show this help"
        echo ""
        echo "Environment Variables:"
        echo "  LIDIS_VERSION    Version string (default: 1.0.0)"
        echo "  BUILD_DIR        Build directory (default: ~/lidis-build)"
        echo "  OUTPUT_DIR       Output directory (default: ~/lidis-output)"
        ;;
    *)
        log_error "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac