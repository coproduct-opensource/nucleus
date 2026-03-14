# Serve pre-built WASM CTF app.
# Build the WASM locally first: cd crates/ctf-engine && trunk build --release
# Then deploy from workspace root: fly deploy
FROM joseluisq/static-web-server:2.41.0-alpine

# Cache bust: mobile responsive v2
COPY crates/ctf-engine/dist /public

ENV SERVER_PORT=8080
ENV SERVER_ROOT=/public
ENV SERVER_LOG_LEVEL=info
ENV SERVER_COMPRESSION=true
ENV SERVER_CACHE_CONTROL_HEADERS="public, no-cache, must-revalidate"

EXPOSE 8080
