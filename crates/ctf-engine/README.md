# The Vault — Nucleus CTF

A browser-native capture-the-flag where you try to **exfiltrate a secret past a
formally-verified permission lattice — and can't.** Each level loads a real
`portcullis::PermissionLattice` profile and tracks exposure with the same
`ExposureSet` production nucleus uses; verdicts are backed by Verus SMT proofs.
It runs entirely in WASM (the game logic is client-side).

It's the thesis made playable: *agent security is an information-flow problem, and
the boundary can be **proven**, not guessed.*

## Play it locally (90 seconds)

```sh
just vault              # serves the pre-built WASM and opens your browser
# or, without `just`:
cd crates/ctf-engine/dist && python3 -m http.server 8799   # → http://127.0.0.1:8799
```

Hosted instance: **https://nucleus-ctf.fly.dev**

## Point an AI at it (the fun part)

`ctf-server` exposes a JSON API + an MCP endpoint so an LLM (ChatGPT, Gemini, an
agent) can attempt the challenge programmatically — and fail the same way:

```
GET  /api/v1/levels            list levels
GET  /api/v1/levels/{level}    level detail
POST /api/v1/attack            submit an exfiltration attempt
POST /api/v1/challenge         run a full challenge
GET  /api                      API docs   ·   GET /openapi.json
/mcp                           MCP (streamable-http) for agent clients
```

`ctf-server` serves the built site from `/public` (a container path) — that path
is for the Docker/Fly deployment, **not** local dev. For local play use `just
vault` (pre-built) or `trunk serve` (fresh, once the build below is fixed).

## Building from source

⚠️ **A fresh `trunk build` / `trunk serve` currently fails.** Honest root cause:
`portcullis::kernel` is always compiled (`pub mod kernel`, ungated) but imports
the `crypto`-feature-gated modules `certificate`, `token`, and `delegation`
(`portcullis/src/kernel.rs`), while this crate depends on portcullis with
`default-features = false, features = ["serde"]` (no `crypto`) to keep the WASM
build clean. So `cargo build --target wasm32-unknown-unknown --features wasm`
errors with `unresolved import crate::certificate / crate::token / delegation`.

Fix options (a real portcullis change, not a CTF change — pick one):
1. **cfg-gate the kernel's crypto deps** — make `kernel`'s `certificate`/`token`/
   `delegation` uses `#[cfg(feature = "crypto")]`, or split a crypto-free kernel
   path, so portcullis builds without `crypto`. (Cleanest; keeps the WASM small.)
2. **Enable `crypto` for the wasm build** in this crate — requires wiring
   `getrandom`'s `js` feature and confirming ed25519 deps compile to
   `wasm32-unknown-unknown`. (Heavier WASM; may surface more wasm-compat work.)

Until that lands, the committed `dist/` is the source of truth for the playable
build, and `just vault` serves it. **Do not assume `dist/` is in sync with `src/`
until the fresh build is restored.**

Prereqs once fixed: `cargo install trunk` + `rustup target add wasm32-unknown-unknown`.
