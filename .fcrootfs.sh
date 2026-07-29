set -euo pipefail
apt-get update -qq && apt-get install -y -qq musl-tools e2fsprogs ca-certificates >/dev/null 2>&1
ln -sf "$(command -v musl-gcc)" /usr/local/bin/aarch64-linux-musl-gcc
rustup target add aarch64-unknown-linux-musl >/dev/null 2>&1
cargo build --release --target aarch64-unknown-linux-musl -p nucleus-guest-init 2>&1|tail -1
export DEBIAN_TARBALL=/out/debian-arm64.tar.gz ROOTFS_DIR=/build/rootfs ROOTFS_IMG=/build/rootfs.ext4 ROOTFS_SIZE_MB=512
mkdir -p /build; bash scripts/firecracker/build-rootfs.sh >/dev/null 2>&1
cp /build/rootfs.ext4 /out/rootfs_noloop.ext4; echo "built noloop"
