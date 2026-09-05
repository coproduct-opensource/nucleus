# Multi-stage build for nucleus-oidc-provider.
# Final image: ~50 MB distroless-cc base + statically-linked-libc-free binary.

# ─── Stage 1: build ─────────────────────────────────────────────────────
FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder

# System deps required to build openssl/rustls/age C crypto.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the entire workspace so path-deps resolve. We rely on the
# workspace Cargo.lock for reproducible builds.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build only the OP binary (release).
RUN cargo build --release --bin nucleus-oidc-provider -p nucleus-oidc-provider

# ─── Stage 2: runtime ───────────────────────────────────────────────────
# distroless/cc: minimal — has libssl, libc, ca-certificates, nothing else.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

WORKDIR /app

# Copy the static binary. Distroless is read-only; the persistent
# keystore goes on the mounted volume at /data.
COPY --from=builder /build/target/release/nucleus-oidc-provider /app/nucleus-oidc-provider

# Non-root by default — distroless `:nonroot` tag drops to UID 65532.
USER nonroot:nonroot

EXPOSE 8080
EXPOSE 9080

# Use exec form so SIGTERM reaches the binary directly for graceful
# shutdown (axum::serve.with_graceful_shutdown).
ENTRYPOINT ["/app/nucleus-oidc-provider"]
