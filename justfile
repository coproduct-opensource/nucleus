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
    @echo "See it deny:   just x402-deny    # IFC gate refuses an unsafe flow (403) BEFORE payment"
    @echo ""
    @echo "GET /paid        safe flow   → IFC ALLOW → pay → result + receipt"
    @echo "GET /paid-unsafe unsafe flow → IFC DENY  → 403, you are NOT charged"
    @echo ""
    @echo "Both routes are IFC-gated + receipted by nucleus-verify-commerce."

# Run an x402 seller on Base Sepolia (needs SELLER_ADDRESS). Paid route is IFC-gated.
x402-seller:
    cd examples/x402-sepolia && cargo run --quiet --bin seller

# Pay an x402 endpoint on Base Sepolia (needs X402_PRIVATE_KEY; TESTNET only).
x402-pay url="http://127.0.0.1:4021/paid":
    cd examples/x402-sepolia && TARGET_URL={{url}} cargo run --quiet --bin buyer

# Hit the IFC-UNSAFE route: the gate DENIES (403) before payment — you are NOT
# charged. Shows the nucleus IFC gate refusing a lethal-trifecta flow up front.
x402-deny url="http://127.0.0.1:4021/paid-unsafe":
    cd examples/x402-sepolia && TARGET_URL={{url}} cargo run --quiet --bin buyer

# One-shot contrast: starts the seller, runs BOTH buyer paths (pay-allow + deny),
# proves the on-chain balance delta (if `cast` is present), then stops the seller.
# Needs SELLER_ADDRESS + X402_PRIVATE_KEY (TESTNET only — never mainnet/real funds).
x402-demo:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${SELLER_ADDRESS:?set SELLER_ADDRESS (your Base Sepolia receiving address)}"
    : "${X402_PRIVATE_KEY:?set X402_PRIVATE_KEY (a TESTNET key holding Base Sepolia USDC)}"
    RPC="https://sepolia.base.org"; USDC="0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    cd examples/x402-sepolia
    echo "building seller + buyer…"; cargo build --quiet --bin seller --bin buyer
    BIND=127.0.0.1:4021 ./target/debug/seller >/tmp/x402-demo-seller.log 2>&1 &
    SELLER_PID=$!; trap 'kill $SELLER_PID 2>/dev/null || true' EXIT
    for _ in $(seq 1 40); do curl -fsS -o /dev/null "http://127.0.0.1:4021/paid-unsafe" 2>/dev/null && break || true; sleep 0.25; done
    bal() { cast call "$USDC" "balanceOf(address)(uint256)" "$1" --rpc-url "$RPC" 2>/dev/null | sed 's/ .*//'; }
    HAVE_CAST=0; command -v cast >/dev/null 2>&1 && HAVE_CAST=1
    if [ "$HAVE_CAST" = 1 ]; then BUYER=$(cast wallet address --private-key "$X402_PRIVATE_KEY"); B0=$(bal "$BUYER"); fi
    echo; echo "── 1) SAFE flow: GET /paid  (gate ALLOWS → buyer pays → 200) ─────────────"
    TARGET_URL=http://127.0.0.1:4021/paid ./target/debug/buyer
    if [ "$HAVE_CAST" = 1 ]; then B1=$(bal "$BUYER"); fi
    echo; echo "── 2) UNSAFE flow: GET /paid-unsafe  (gate DENIES → 403, NOT charged) ────"
    TARGET_URL=http://127.0.0.1:4021/paid-unsafe ./target/debug/buyer
    if [ "$HAVE_CAST" = 1 ]; then B2=$(bal "$BUYER"); echo; \
      python3 -c "print(f'on-chain buyer USDC:  start={int(\"$B0\")/1e6:.6f}  after pay={int(\"$B1\")/1e6:.6f} (Δ {(int(\"$B1\")-int(\"$B0\"))/1e6:+.6f})  after deny={int(\"$B2\")/1e6:.6f} (Δ {(int(\"$B2\")-int(\"$B1\"))/1e6:+.6f})')"; fi
    echo; echo "same gate, same price, opposite outcome — decided by the declared data-flow."

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
