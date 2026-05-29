# Multi-stage Rust build for the nucleus-verifier-service binary.
#
# Stage 1 builds the binary against a workspace checkout; stage 2 runs
# it on a thin distroless base. Build context is the *workspace root*,
# not this crate's directory:
#
#   docker build -f crates/nucleus-verifier-service/Dockerfile -t nucleus-verifier .

FROM rust:1.95-slim-bookworm AS build
WORKDIR /work
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/work/target \
    cargo build --release --bin nucleus-verifier-service && \
    cp /work/target/release/nucleus-verifier-service /usr/local/bin/nucleus-verifier-service

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /usr/local/bin/nucleus-verifier-service /usr/local/bin/nucleus-verifier-service
EXPOSE 8080
# Default env: bind on all interfaces, DB on the mounted volume. The
# binary auto-creates the file + runs embedded migrations on first
# connect; the volume mount comes from fly.toml's [mounts] block.
# NUCLEUS_VERIFIER_SIGNING_KEY MUST be supplied via `fly secrets set`
# in production (see fly.toml comment).
ENV NUCLEUS_VERIFIER_BIND=0.0.0.0:8080
ENV NUCLEUS_VERIFIER_DB="sqlite:/data/verifier.db"
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/nucleus-verifier-service"]
