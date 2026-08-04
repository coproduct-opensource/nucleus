set -euo pipefail
apt-get update -qq && apt-get install -y -qq e2fsprogs ca-certificates >/dev/null 2>&1
export DEBIAN_TARBALL=/out/debian-arm64.tar.gz ROOTFS_DIR=/build/rootfs ROOTFS_IMG=/build/rootfs.ext4 ROOTFS_SIZE_MB=512
export TOOL_PROXY_AUTH_SECRET="boot-experiment-auth-secret"
mkdir -p /build
bash scripts/firecracker/build-rootfs.sh 2>&1 | grep -E "CA bundle|WARNING|Included|nucleus-|/init" | head -8
cp /build/rootfs.ext4 /out/rootfs2.ext4; ls -lh /out/rootfs2.ext4
