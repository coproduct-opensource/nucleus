# Multi-stage build: native axum server + pre-built WASM static site.
#
# The WASM site (crates/ctf-engine/dist/) is built locally with Trunk
# and committed. This Dockerfile only builds the native API server.

# Builder image must satisfy the workspace `rust-version = 1.95` floor
# (portcullis et al. reject older toolchains). `rust:1-slim` tracks the
# latest stable 1.x — bump explicitly if a newer floor is set.
FROM rust:1-slim AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p ctf-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/ctf-server /usr/local/bin/ctf-server
COPY crates/ctf-engine/dist /public

ENV PORT=8080
EXPOSE 8080
CMD ["ctf-server"]
