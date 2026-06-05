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

```sh
cargo install trunk
rustup target add wasm32-unknown-unknown
cd crates/ctf-engine && trunk build      # or `just vault-fresh` to build + serve
```

The fresh build works. It was previously broken because `portcullis::kernel` is
always compiled but used the `crypto`-feature-gated `certificate`/`token`/
`delegation` modules, while this crate builds portcullis without `crypto` (ring
can't compile to WASM). Fixed by making those modules' DATA types always-compiled
and gating only the `ring`-using functions (`mint`/`delegate`/`verify_certificate`,
`Token::verify`) behind `crypto` — the kernel needs the types, not the signing.

`Trunk.toml` pins the `wasm_bindgen` CLI to the `wasm-bindgen` crate version in
`Cargo.lock` (currently `0.2.122`); the bindgen schema must match exactly. Bump
both in lockstep (`cargo update -p wasm-bindgen` + the `[tools]` pin) on upgrade.

The committed `dist/` is the pre-built artifact `just vault` serves; it is now
regenerated from source by `trunk build`.
