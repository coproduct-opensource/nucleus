# syntax=docker/dockerfile:1
# The Fly worker image.
#
# WHY THIS IS NOT docker/Dockerfile.runner. It would be better if it were: the workflows' 103
# `if: runner.environment == 'github-hosted'` install steps are skipped on EVERY self-hosted
# runner, so a tool the k3s image has and this one lacks is a job that cannot run at all — which
# is how `deny` failed four ways on the first post-cut-over run. But a Fly Machine's root
# filesystem is capped at 8 GB uncompressed, and the k3s image unpacks to more than that: every
# machine in the pool answered "Not enough space to unpack image, possibly exceeds maximum of 8GB
# uncompressed" and the pool wedged with twenty machines stuck in `starting`.
#
# So the split is forced by the substrate, and it is drawn where the sizes are: everything a
# routed job needs that is small enough (the cargo tools, zig) is baked here at the SAME pins
# docker/Dockerfile.runner uses; the toolchain-sized pieces (elan + Lean, aeneas + charon and
# their nightlies, the dylint nightly with rustc-dev) are not, and the lanes that need them stay
# on hosted runners — see the `runs-on` comments in those workflows.
#
# Keep the ARG versions here and in docker/Dockerfile.runner equal. ci/fly-runner-tool-parity.sh
# checks that they are.
FROM ghcr.io/actions/actions-runner:2.337.0@sha256:e5496277be5d09bc968b3d64911b74e219ac4a3f2edce956a3ecf9271bea1ef4
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential clang lld llvm pkg-config cmake libssl-dev protobuf-compiler \
    musl-tools e2fsprogs git zstd xz-utils python3 python-is-python3 python3-dev \
    python3-requests ca-certificates curl jq procps time xxd bc patchelf \
 && rm -rf /var/lib/apt/lists/*

# gh: release downloads the hosted path uses, and any `gh api` a gate script makes.
RUN set -eux; \
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /usr/share/keyrings/githubcli-archive-keyring.gpg; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list; \
    apt-get update; apt-get install -y --no-install-recommends gh; rm -rf /var/lib/apt/lists/*; gh --version | head -1

ARG SCCACHE_VERSION=0.17.0
ARG JUST_VERSION=1.58.0
RUN set -eux; \
    arch="$(uname -m)"; \
    curl -fsSL "https://github.com/mozilla/sccache/releases/download/v${SCCACHE_VERSION}/sccache-v${SCCACHE_VERSION}-${arch}-unknown-linux-musl.tar.gz" | tar xz -C /tmp; \
    install -m 0755 /tmp/sccache-v${SCCACHE_VERSION}-${arch}-unknown-linux-musl/sccache /usr/local/bin/sccache; \
    rm -rf /tmp/sccache-*; \
    curl -fsSL "https://github.com/casey/just/releases/download/${JUST_VERSION}/just-${JUST_VERSION}-${arch}-unknown-linux-musl.tar.gz" | tar xz -C /usr/local/bin just; \
    sccache --version; just --version

# zig: a C cross-compiler with bundled musl for every target, so the musl type-check does not
# need a hosted runner that happened to have x86_64-linux-musl-gcc.
ARG ZIG_VERSION=0.16.0
ARG ZIG_SHA256_X86_64=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
ARG ZIG_SHA256_AARCH64=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in x86_64) sum="$ZIG_SHA256_X86_64";; aarch64) sum="$ZIG_SHA256_AARCH64";; *) echo "unsupported arch $arch" >&2; exit 1;; esac; \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${arch}-linux-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz; \
    echo "$sum  /tmp/zig.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/zig && tar xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    ln -s /opt/zig/zig /usr/local/bin/zig; rm -f /tmp/zig.tar.xz; zig version

USER runner
ENV RUSTUP_HOME=/home/runner/.rustup CARGO_HOME=/home/runner/.cargo \
    PATH=/home/runner/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_SHA256_X86_64=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
ARG RUSTUP_SHA256_AARCH64=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in x86_64) sum="$RUSTUP_SHA256_X86_64";; aarch64) sum="$RUSTUP_SHA256_AARCH64";; *) echo "unsupported arch $arch" >&2; exit 1;; esac; \
    curl -fsSL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${arch}-unknown-linux-gnu/rustup-init" -o /tmp/rustup-init.download; \
    echo "$sum  /tmp/rustup-init.download" | sha256sum -c -; \
    install -m 0755 /tmp/rustup-init.download /tmp/rustup-init; rm -f /tmp/rustup-init.download; \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain 1.96.1 -c clippy -c rustfmt; \
    rm -f /tmp/rustup-init; \
    rustup target add x86_64-unknown-linux-musl wasm32-unknown-unknown --toolchain 1.96.1; \
    rustc --version; cargo --version

# The cargo tools the routed workflows do NOT install on a self-hosted runner. Same pins as
# docker/Dockerfile.runner. cargo-dylint is here but its nightly is not: the dylint lane installs
# that itself.
ARG CARGO_AUDIT_VERSION=0.22.0
ARG CARGO_LLVM_COV_VERSION=0.9.0
ARG CARGO_HACK_VERSION=0.6.45
ARG CARGO_NEXTEST_VERSION=0.9.143
ARG CARGO_DENY_VERSION=0.20.2
ARG CARGO_ZIGBUILD_VERSION=0.23.4
RUN set -eux; \
    cargo install cargo-audit --version ${CARGO_AUDIT_VERSION} --locked --no-default-features; \
    cargo install cargo-llvm-cov --version ${CARGO_LLVM_COV_VERSION} --locked; \
    cargo install cargo-hack --version ${CARGO_HACK_VERSION} --locked; \
    cargo install cargo-nextest --version ${CARGO_NEXTEST_VERSION} --locked; \
    cargo install cargo-deny --version ${CARGO_DENY_VERSION} --locked; \
    cargo install cargo-zigbuild --version ${CARGO_ZIGBUILD_VERSION} --locked; \
    rm -rf /home/runner/.cargo/registry /home/runner/.cargo/git /home/runner/.cargo/.package-cache; \
    mkdir -p /home/runner/.cargo/registry /home/runner/.cargo/git /home/runner/.cache; \
    cargo audit --version; cargo llvm-cov --version; cargo hack --version; \
    cargo nextest --version; cargo deny --version; cargo-zigbuild --version

# elan + the one Lean toolchain every lean project pins, per runner user like rustup. The Lean
# lanes install elan only when `runner.environment == 'github-hosted'` — on a self-hosted runner
# they assume the image has it — so an image without elan fails them with `lake: command not
# found`, which is a REQUIRED check and therefore ejects merge-queue entries. It was left out on
# the first pass because the full k3s image does not fit Fly's 8 GB rootfs cap; elan and one
# toolchain on top of this much smaller image do. Mathlib's cache is fetched per job, not baked.
ARG LEAN_TOOLCHAIN=leanprover/lean4:v4.30.0-rc2
ARG ELAN_VERSION=v4.2.4
ARG ELAN_SHA256_X86_64=42b94d4244e8353142c456ec0e4ca6528fd898a6c604d4059f494e706e431f63
ARG ELAN_SHA256_AARCH64=05febd124d84ebf994b2e7479922a5650b1e950c17ae3bd1ddd776b65bb72bf9
ENV ELAN_HOME=/home/runner/.elan \
    PATH=/home/runner/.elan/bin:/home/runner/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in x86_64) sum="$ELAN_SHA256_X86_64";; aarch64) sum="$ELAN_SHA256_AARCH64";; *) echo "unsupported arch $arch" >&2; exit 1;; esac; \
    curl -fsSL "https://github.com/leanprover/elan/releases/download/${ELAN_VERSION}/elan-${arch}-unknown-linux-gnu.tar.gz" -o /tmp/elan.tar.gz; \
    echo "$sum  /tmp/elan.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/elan.tar.gz -C /tmp elan-init; rm -f /tmp/elan.tar.gz; \
    /tmp/elan-init -y --no-modify-path --default-toolchain "${LEAN_TOOLCHAIN}"; \
    rm -f /tmp/elan-init; lean --version; lake --version

# Paths are relative to the build context, which is the repository root.
COPY ci/fly-runner/cargo-config.toml /home/runner/.cargo/config.toml
USER root
RUN printf '#!/bin/sh\nexec cc -fuse-ld=lld "$@"\n' > /usr/local/bin/cc-lld && chmod 0755 /usr/local/bin/cc-lld \
 && chown runner:runner /home/runner/.cargo/config.toml && cc-lld --version | head -1
COPY --chmod=755 ci/fly-runner/entrypoint.sh /usr/local/bin/fly-runner
COPY --chmod=755 ci/fly-runner/job-started.sh ci/fly-runner/job-completed.sh /usr/local/bin/

# A Fly Machine rootfs is capped at 8 GB UNCOMPRESSED, and exceeding it is not a build error: the
# push succeeds, and every machine that pulls the image logs "Not enough space to unpack image"
# and sits in `starting` forever. The fleet then looks like a slow boot, not a failure — 24
# machines wedged for 46 minutes the day this image grew past the cap. Registry size is no guide:
# the image that broke it was 2.54 GB compressed and the one that boots is 1.78 GB.
#
# So measure the thing the cap is actually on, here, where it can still refuse. The budget leaves
# room for the layers below this one and for the job's own scratch space.
ARG ROOTFS_BUDGET_MB=7000
RUN set -eux; \
    used="$(du -sxm --exclude=/proc --exclude=/sys --exclude=/dev / | cut -f1)"; \
    echo "rootfs: ${used} MB used of a ${ROOTFS_BUDGET_MB} MB budget (Fly caps the machine at 8192)"; \
    if [ "$used" -gt "$ROOTFS_BUDGET_MB" ]; then \
        echo "REFUSING: this image does not fit a Fly Machine. Trim it or move the weight to a volume." >&2; \
        exit 1; \
    fi

ENTRYPOINT ["/usr/local/bin/fly-runner"]
