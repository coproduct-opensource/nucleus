# Multi-stage Rust build for the nucleus-verifier-service binary.
#
# Stage 1 builds the binary against a workspace checkout; stage 2 runs
# it on a thin distroless base. Build context is the *workspace root*,
# not this crate's directory:
#
#   docker build -f crates/nucleus-verifier-service/Dockerfile -t nucleus-verifier .

FROM rust:1.85-slim-bookworm AS build
WORKDIR /work
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/work/target \
    cargo build --release --bin nucleus-verifier-service && \
    cp /work/target/release/nucleus-verifier-service /usr/local/bin/nucleus-verifier-service

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /usr/local/bin/nucleus-verifier-service /usr/local/bin/nucleus-verifier-service
EXPOSE 8080
ENV NUCLEUS_VERIFIER_BIND=0.0.0.0:8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/nucleus-verifier-service"]
