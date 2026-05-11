# nucleus-lineage

> **Status: alpha.** A per-call SPIFFE-ID derivation library with an `O_APPEND`-mode JSONL log and a `LocalIssuer` for demos. Edge signing, hash chaining, and a SPIRE-backed `IdentityFetcher` impl are roadmap, not shipped. Read [Honest constraints](#honest-constraints) before depending on this for anything you care about.

`nucleus-lineage` extends [SPIFFE](https://spiffe.io/) workload identity from the *pod* level down to the *individual call* level. Each tool invocation, LLM call, or derived artifact mints a child SPIFFE ID whose path encodes its lineage and whose suffix is a content hash. With signing landed (roadmap), the result will be a tamper-evident, content-addressed DAG that answers **"where did this data come from?"** with cryptographic evidence rather than inference. Today it answers it with content hashes plus a parent pointer — useful, but not adversary-resistant on its own.

## The path scheme

```
spiffe://<trust>/ns/<ns>/sa/<sa>                                   ← pod (root)
  /call/<uuid>/tool/<tool>                                         ← tool call
  /call/<uuid>/llm/<provider>/prompt/sha256:<hex>                  ← LLM input
  /call/<uuid>/llm/<provider>/response/sha256:<hex>                ← LLM output
  /call/<uuid>/derived/sha256:<hex>                                ← downstream artifact
```

Identical content → identical content-hash suffix (regardless of derivation path), so re-deriving the same value from the same parents is recognizable. The full path is a human-readable witness of how this byte-string came to exist.

## Quick demo

A 3-step workflow ships as `examples/three_step_demo.rs`:

```bash
$ cargo run -p nucleus-lineage --example three_step_demo
=== nucleus-lineage three-step demo ===
log:         ./nucleus-lineage.jsonl
external:    mock LLM (default)

admitted pod: spiffe://demo.nucleus.local/ns/agents/sa/lineage-demo
step 1 ✔ Bash → spiffe://…/call/cca7fa46…/tool/Bash/sha256:b534e3bf… (25 bytes)
step 2 ✔ Write → spiffe://…/call/bde8f048…/tool/Write/sha256:b534e3bf… (/tmp/...)
step 3a ✔ LLM prompt → spiffe://…/call/388064f0…/llm/anthropic/prompt/sha256:b534e3bf…
    mock-llm: verified JWT (self-loop), sub=spiffe://…, jti=684ee954…, exp_in=300s
step 3b ✔ LLM response → spiffe://…/call/63b43cec…/llm/anthropic/response/sha256:2a6f4cc9… (476 bytes)

done. lineage log written to ./nucleus-lineage.jsonl
walk it with:
  nucleus lineage 'spiffe://…/llm/anthropic/response/sha256:2a6f4cc9…' --log ./nucleus-lineage.jsonl
```

The "mock-llm: verified JWT" line is honest about what's verified: the JWT was minted by the `LocalIssuer` and verified using the **same in-process key** the issuer mints with. This proves JWT well-formedness, not cross-trust federation. A real relying party would fetch a JWKS from a separate trust anchor — that's roadmap.

Then walk the chain back to its source:

```bash
$ nucleus lineage 'spiffe://…/sha256:2a6f4cc9…' --log ./nucleus-lineage.jsonl
lineage ↑ to spiffe://…/sha256:2a6f4cc9…
  [llm/anthropic/response] spiffe://…/sha256:2a6f4cc9… sha256=2a6f4cc91f3d…
    ← spiffe://…/llm/anthropic/prompt/sha256:b534e3bf…
  [llm/anthropic/prompt]   spiffe://…/sha256:b534e3bf… sha256=b534e3bfc97b…
    ← spiffe://…/tool/Write/sha256:b534e3bf…
  [tool/Write]             spiffe://…/sha256:b534e3bf… sha256=b534e3bfc97b…
    ← spiffe://…/tool/Bash/sha256:b534e3bf…
  [tool/Bash]              spiffe://…/sha256:b534e3bf… sha256=b534e3bfc97b…
    ← spiffe://demo.nucleus.local/ns/agents/sa/lineage-demo
  [pod_admit]              spiffe://demo.nucleus.local/ns/agents/sa/lineage-demo
```

For Graphviz output: `--format dot`. For machine-readable JSON: `--format json`.

## What this crate ships

| Module | Purpose |
|---|---|
| `id::CallSpiffeId` | SPIFFE-format identity. Validates `/call/<uuid>/...` suffix structure and content-hash format; full SPIFFE ID grammar enforcement is roadmap. Round-trips through serde. |
| `edge::LineageEdge` | One record in the DAG: `(child, parents[], kind, content_hash, ts, attrs)`. JSON wire format. **Edges are not yet signed.** |
| `sink::LineageSink` | Trait for persistence. `InMemorySink` (tests) + `JsonlSink` (file-backed, `O_APPEND` mode — not tamper-evident, see below) ship in this crate. |
| `issuer::IdentityFetcher` | Trait for JWT-SVID minting. `LocalIssuer` (Ed25519, in-process, demo-only) ships here. **No SPIRE-backed impl exists in this repo yet.** |

## Honest constraints

The list below is what's missing today. Most items are tracked for follow-up PRs; this README will be updated as each lands.

- **`LocalIssuer` is demo-only.** It signs with an ephemeral in-process Ed25519 key, has no JWKS publication, no key rotation, no persistence. It is exported publicly and currently has no programmatic guard against being wired into production code. Do not use it as a production `IdentityFetcher`. (Tracked: feature-gate behind a `dev` cargo feature.)
- **No SPIRE-backed `IdentityFetcher`.** `nucleus-identity`'s existing `spire` feature handles X.509 SVIDs only; the JWT-SVID API surface is not yet wired in. The trait is the integration point; the impl has to be written.
- **Edges are not signed.** `LineageEdge` carries the child/parents/kind/content_hash/ts/attrs but no `Proof { kid, alg, sig }` field. Anyone with write access to the JSONL log can fabricate parent relationships — including claiming a victim pod's SPIFFE ID as the parent of an attacker artifact. The walker (`nucleus lineage`) trusts edge-claimed parents; it does not perform structural reconciliation against `CallSpiffeId::parent()`. (Tracked: add `Proof` field; sign edges; walker verifies.)
- **`JsonlSink` is `O_APPEND`-mode, not tamper-evident.** No hash chain (`prev_hash`), no signatures, no truncation detection. The file is process-local; concurrent multi-process writes can interleave bytes. The existing `nucleus-audit` crate has the receipt-chain pattern this crate should adopt.
- **`--real-claude` mode does not exercise SPIFFE WIF.** It uses the long-lived `ANTHROPIC_API_KEY` for wire auth and only *records* the SPIFFE ID locally. The recorded edge attributes (`audience=https://api.anthropic.com`, `jwt_jti=...`) imply that a JWT-SVID was on the wire; the JWT was not. (Tracked: rename the recorded attrs to `wire_auth=api_key, recorded_subject=...`.)
- **`CallSpiffeId::parse` accepts malformed inputs.** Currently passes: NUL bytes, RTL Unicode overrides, double slashes, uppercase `/CALL/`, query/fragment/userinfo, and several other forms forbidden by the SPIFFE ID spec. Negative tests are not yet present. (Tracked: parser hardening + negative test suite.)
- **Anthropic-side echo-back is unidirectional and inherent.** When a JWT-SVID is presented to the Anthropic API, the `sub` claim appears in their audit log — but the response payload does not carry a SPIFFE ID we can attach to derived data. This is a property of WIF, not a fix-it-here issue.
- **Process-local sink only.** Cross-process / cross-host lineage requires a remote sink — straightforward extension via the trait, not yet written.

**This crate binds *who called*, not *what data was in the call*.** Prompt-body taint still requires the existing portcullis IFC machinery. SPIFFE lineage and IFC labels compose; they do not replace each other.

## Categorical framing (roadmap, not load-bearing)

Per-call SPIFFE IDs *will* lift the workload category to a bicategory where morphisms (calls) carry identities — once edges are signed and the walker actually verifies the cocycle condition (signed restriction maps, gluing across overlap). Today the structure exists in the path scheme but is not enforced computationally. The connection to the `alignment_tax = rank(H¹(IFC_sheaf))` line of work in `portcullis-core/lean/` is suggestive, not formal: those Lean theorems are about IFC posets, not about per-call SPIFFE provenance graphs. Treat this section as design intent until the `verify_glue` function lands.

See `project_per_call_spiffe_lineage.md` in the project memory for the longer argument.

## License

MIT, same as the rest of nucleus.
