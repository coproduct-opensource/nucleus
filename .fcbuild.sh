set -euo pipefail
echo "=== installing toolchain ==="
apt-get update -qq
apt-get install -y -qq musl-tools musl-dev e2fsprogs curl ca-certificates pkg-config >/dev/null 2>&1
# The linker name gap: Ubuntu aarch64 ships `musl-gcc`, .cargo/config.toml wants
# `aarch64-linux-musl-gcc`. On a NATIVE aarch64 host they are the same compiler,
# so a symlink is correct here (it would NOT be on a cross host).
if [ ! -e /usr/local/bin/aarch64-linux-musl-gcc ]; then
  ln -s "$(command -v musl-gcc)" /usr/local/bin/aarch64-linux-musl-gcc
fi
aarch64-linux-musl-gcc --version | head -1
rustup target add aarch64-unknown-linux-musl
echo "=== building guest binaries (release, musl) ==="
cargo build --release --target aarch64-unknown-linux-musl \
  -p nucleus-guest-init -p nucleus-tool-proxy -p nucleus-net-probe 2>&1 | tail -25
echo "=== artifacts ==="
ls -la /w/target/aarch64-unknown-linux-musl/release/ | grep -E "nucleus-(guest-init|tool-proxy|net-probe)$"
file /w/target/aarch64-unknown-linux-musl/release/nucleus-guest-init
