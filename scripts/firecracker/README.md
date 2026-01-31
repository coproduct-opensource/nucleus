# Firecracker Build Scripts

These scripts build a minimal Debian slim rootfs and scratch disk for the demo.

## Requirements
- Linux host with `/dev/kvm`
- `docker`
- `mke2fs`

## Build

```bash
# Build proxy
cargo build -p nucleus-tool-proxy --release --target x86_64-unknown-linux-musl

# Create scratch
./scripts/firecracker/build-scratch.sh

# Create rootfs
./scripts/firecracker/build-rootfs.sh
```

Provide a kernel at `./build/firecracker/vmlinux` (pinned, known-good).
