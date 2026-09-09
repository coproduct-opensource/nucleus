# syntax=docker/dockerfile:1
# Rust build lane only: workspace tests and Clippy, not the proof-toolchain fleet.
FROM ghcr.io/actions/actions-runner:2.337.0@sha256:e5496277be5d09bc968b3d64911b74e219ac4a3f2edce956a3ecf9271bea1ef4
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential clang lld pkg-config cmake libssl-dev protobuf-compiler \
    git zstd xz-utils python3 python3-dev python3-venv python3-pip python3-requests \
    ca-certificates curl jq procps time \
 && rm -rf /var/lib/apt/lists/*
COPY tools.json /tmp/tools.json
COPY --chmod=755 install-tools.sh /tmp/install-tools.sh
RUN /tmp/install-tools.sh /tmp/tools.json && rm /tmp/tools.json /tmp/install-tools.sh \
 && printf '#!/bin/sh\nexec cc -fuse-ld=lld "$@"\n' > /usr/local/bin/cc-lld \
 && chmod 0755 /usr/local/bin/cc-lld
USER runner
ENV RUSTUP_HOME=/home/runner/.rustup CARGO_HOME=/home/runner/.cargo \
    PATH=/home/runner/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN curl -fsSL https://static.rust-lang.org/rustup/archive/1.29.1/x86_64-unknown-linux-gnu/rustup-init -o /tmp/rustup-init \
 && echo 'dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71  /tmp/rustup-init' | sha256sum -c - \
 && chmod 0755 /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain 1.96.1 -c clippy -c rustfmt \
 && rustup target add wasm32-unknown-unknown \
 && rm /tmp/rustup-init
COPY cargo-config.toml /home/runner/.cargo/config.toml
COPY --chmod=755 entrypoint.sh /usr/local/bin/fly-runner
COPY --chmod=755 job-started.sh job-completed.sh /usr/local/bin/
USER root
ENTRYPOINT ["/usr/local/bin/fly-runner"]
