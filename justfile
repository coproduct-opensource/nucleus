# nucleus — dev recipes.  `just <recipe>`  (https://github.com/casey/just)

# List recipes.
default:
    @just --list

# ── The 90-second hooks ──────────────────────────────────────────────────────

# 30s: IFC in 4 scenarios — watch a prompt-injection write get DENIED by ancestry.
demo:
    cargo run -q -p nucleus-ifc --example ifc_demo

# Play "The Vault": exfiltrate a secret past a formally-verified lattice (browser/WASM).
vault port="8799":
    @echo "The Vault → http://127.0.0.1:{{port}}   (serving pre-built WASM; Ctrl-C to stop)"
    @( sleep 1 ; command -v open >/dev/null 2>&1 && open "http://127.0.0.1:{{port}}" || command -v xdg-open >/dev/null 2>&1 && xdg-open "http://127.0.0.1:{{port}}" || true ) &
    cd crates/ctf-engine/dist && python3 -m http.server {{port}}

# Rebuild The Vault WASM from source then serve (needs trunk + wasm32 target).
vault-fresh:
    cd crates/ctf-engine && trunk serve --open

# ── Everyday ─────────────────────────────────────────────────────────────────

# Rust-native task runner. `just xtask <command>` (e.g. `just xtask scripts`).
xtask *args:
    cargo xtask {{args}}

# Build every workspace crate standalone to catch isolation/feature breakages.
check-isolation:
    cargo xtask check-isolation

# Run the test suite.
test:
    cargo test --all-features

# Format + lint gate (matches CI).
check:
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
