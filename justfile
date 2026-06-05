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

# ── Signed, IFC-attested agents ──────────────────────────────────────────────

# Sign an Agent Card that declares an IFC runtime-guarantee profile, then verify
# it (incl. tamper-detection). Ephemeral key; production uses OIDC-keyless.
agent-sign:
    cargo run -q -p nucleus-agent-card --example agent_sign --features sign

# ── x402 on Base Sepolia (TESTNET only — never mainnet / real funds) ──────────

# Print the Base Sepolia x402 bootstrap config + faucet links (instant).
x402-info:
    @echo "x402 bootstrap — Base Sepolia TESTNET (chain eip155:84532)"
    @echo "  facilitator : https://facilitator.x402.rs   (or https://x402.org/facilitator)"
    @echo "  test ETH    : https://www.alchemy.com/faucets/base-sepolia"
    @echo "  test USDC   : https://faucet.circle.com   (select Base Sepolia)"
    @echo ""
    @echo "Seller (30s):  export SELLER_ADDRESS=0x<your base-sepolia address> && just x402-seller"
    @echo "Pay it:        export X402_PRIVATE_KEY=0x<TESTNET key w/ bUSDC>      && just x402-pay"
    @echo ""
    @echo "The paid route is also IFC-gated + receipted by nucleus-verify-commerce."

# Run an x402 seller on Base Sepolia (needs SELLER_ADDRESS). Paid route is IFC-gated.
x402-seller:
    cd examples/x402-sepolia && cargo run --quiet --bin seller

# Pay an x402 endpoint on Base Sepolia (needs X402_PRIVATE_KEY; TESTNET only).
x402-pay url="http://127.0.0.1:4021/paid":
    cd examples/x402-sepolia && TARGET_URL={{url}} cargo run --quiet --bin buyer

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
