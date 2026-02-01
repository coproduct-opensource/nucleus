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

# Build guest init
cargo build -p nucleus-guest-init --release --target x86_64-unknown-linux-musl

# Build TCP probe
cargo build -p nucleus-net-probe --release --target x86_64-unknown-linux-musl

# Create scratch
./scripts/firecracker/build-scratch.sh

# Create rootfs
./scripts/firecracker/build-rootfs.sh
```

Provide a kernel at `./build/firecracker/vmlinux` (pinned, known-good).

## Network test

```bash
sudo ./scripts/firecracker/test-network.sh
```

Set `CHECK_CONNECTIVITY=1` to attempt outbound TCP connects inside the netns.
The connectivity probe runs inside the guest via `nucleus-net-probe`.
