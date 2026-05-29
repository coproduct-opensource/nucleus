# Multi-stage Rust build for the nucleus-control-plane-server binary.
#
# Build context is the workspace root:
#   docker build -f crates/nucleus-control-plane-server/Dockerfile -t nucleus-control-plane .

FROM rust:1.95-slim-bookworm AS build
WORKDIR /work
# protoc is required at build time by nucleus-proto.
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/work/target \
    cargo build --release --bin nucleus-control-plane-server && \
    cp /work/target/release/nucleus-control-plane-server /usr/local/bin/nucleus-control-plane-server

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /usr/local/bin/nucleus-control-plane-server /usr/local/bin/nucleus-control-plane-server
EXPOSE 8080
EXPOSE 9080
ENV NUCLEUS_BIND=0.0.0.0:8080
ENV NUCLEUS_GRPC_BIND=0.0.0.0:9080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/nucleus-control-plane-server"]
