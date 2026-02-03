# Nucleus Makefile
# Primary build targets for development and CI

.PHONY: all build test clippy fmt rootfs clean help

# Default target
all: build

# Build all crates
build:
	cargo build --workspace

# Build release binaries
release:
	cargo build --workspace --release

# Run all tests
test:
	cargo test --workspace

# Run clippy lints
clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# Format code
fmt:
	cargo fmt --all

# Check formatting
fmt-check:
	cargo fmt --all -- --check

# Build rootfs for Firecracker microVMs
# This target is designed to run inside a Lima VM (which has Docker)
# Usage: limactl shell nucleus -- make rootfs
rootfs:
	@echo "Building rootfs for Firecracker..."
	@ARCH=$$(uname -m | sed 's/arm64/aarch64/'); \
	if [ "$$ARCH" = "aarch64" ]; then \
		TARGET="aarch64-unknown-linux-musl"; \
	else \
		TARGET="x86_64-unknown-linux-musl"; \
	fi; \
	echo "Architecture: $$ARCH (target: $$TARGET)"; \
	if [ ! -f "target/$$TARGET/release/nucleus-tool-proxy" ]; then \
		echo "Error: Cross-compiled binaries not found."; \
		echo "Run './scripts/cross-build.sh' on macOS first."; \
		exit 1; \
	fi; \
	./scripts/firecracker/build-rootfs.sh --arch "$$ARCH"

# Build rootfs for specific architecture (useful in CI)
rootfs-aarch64:
	./scripts/firecracker/build-rootfs.sh --arch aarch64

rootfs-x86_64:
	./scripts/firecracker/build-rootfs.sh --arch x86_64

# Cross-compile for Linux (run on macOS)
cross-build:
	./scripts/cross-build.sh

# Clean build artifacts
clean:
	cargo clean
	rm -rf build/firecracker

# Run security audit
audit:
	cargo audit

# Run cargo-deny checks
deny:
	cargo deny check

# Generate documentation
docs:
	cargo doc --workspace --no-deps

# Help
help:
	@echo "Nucleus Makefile targets:"
	@echo ""
	@echo "  build        - Build all crates (debug)"
	@echo "  release      - Build all crates (release)"
	@echo "  test         - Run all tests"
	@echo "  clippy       - Run clippy lints"
	@echo "  fmt          - Format code"
	@echo "  fmt-check    - Check code formatting"
	@echo ""
	@echo "  rootfs       - Build Firecracker rootfs (run in Lima VM)"
	@echo "  rootfs-aarch64 - Build rootfs for ARM64"
	@echo "  rootfs-x86_64  - Build rootfs for x86_64"
	@echo "  cross-build  - Cross-compile Linux binaries (run on macOS)"
	@echo ""
	@echo "  clean        - Clean build artifacts"
	@echo "  audit        - Run security audit"
	@echo "  deny         - Run cargo-deny checks"
	@echo "  docs         - Generate documentation"
	@echo ""
	@echo "For macOS development:"
	@echo "  1. ./scripts/cross-build.sh    # On macOS"
	@echo "  2. limactl shell nucleus -- make rootfs  # Build rootfs in Lima"
