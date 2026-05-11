# nucleus-lineage

> Every tool call gets a SPIFFE identity. Every byte of output has a verifiable provenance chain back to its sources.

`nucleus-lineage` extends [SPIFFE](https://spiffe.io/) workload identity from the *pod* level down to the *individual call* level. Each tool invocation, LLM call, or derived artifact mints a child SPIFFE ID whose path encodes its lineage and whose suffix is a content hash. The result: a cryptographically-signed, content-addressed DAG that lets you answer **"where did this data come from?"** with concrete evidence rather than inference.

## The path scheme

```
spiffe://<trust>/ns/<ns>/sa/<sa>                                   ← pod (root)
  /call/<uuid>/tool/<tool>                                         ← tool call
  /call/<uuid>/llm/<provider>/prompt/sha256:<hex>                  ← LLM input
  /call/<uuid>/llm/<provider>/response/sha256:<hex>                ← LLM output
  /call/<uuid>/derived/sha256:<hex>                                ← downstream artifact
```

Identical content → identical content-hash suffix (regardless of derivation path), so re-deriving the same value from the same parents is recognizable. The full path doubles as a human-readable witness of how this byte-string came to exist.

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
    mock-llm: verified JWT, sub=spiffe://…, jti=684ee954…, exp_in=300s
step 3b ✔ LLM response → spiffe://…/call/63b43cec…/llm/anthropic/response/sha256:2a6f4cc9… (476 bytes)

done. lineage log written to ./nucleus-lineage.jsonl
walk it with:
  nucleus lineage 'spiffe://…/llm/anthropic/response/sha256:2a6f4cc9…' --log ./nucleus-lineage.jsonl
```

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
| `id::CallSpiffeId` | SPIFFE-format identity with strict path grammar. Constructors for pod-root + tool / LLM / artifact derivations. Round-trips through serde. |
| `edge::LineageEdge` | One immutable record in the DAG: `(child, parents[], kind, content_hash, ts, attrs)`. Wire format is JSON, kept stable. |
| `sink::LineageSink` | Trait for append-only persistence. `InMemorySink` (tests) + `JsonlSink` (file-backed) ship in this crate. |
| `issuer::IdentityFetcher` | Trait for JWT-SVID minting. `LocalIssuer` (Ed25519, in-process, demo-only) ships here; a SPIRE Workload API impl lives in `nucleus-identity`. |

## Honest constraints

`LocalIssuer` is **demo-only**. It signs with an ephemeral in-process Ed25519 key and is not what you should use in production. For real deployments you want a SPIRE Agent (or any SPIFFE-conformant issuer) backing the `IdentityFetcher` trait — see `nucleus-identity`'s `spire` feature for the production path.

The Anthropic side of the lineage is **unidirectional**. When a JWT-SVID is presented to the Anthropic API, the `sub` claim appears in their audit log — but the response payload doesn't carry a SPIFFE ID we can attach to derived data. Lineage from prompt → response is established on the nucleus side from the timing + content hashes; it is not echoed back by the relying party. This is an inherent property of the WIF protocol, not a defect of this implementation.

The default `LineageSink` is process-local. Cross-process / cross-host lineage requires a remote sink — straightforward extension via the trait, not yet implemented in this crate.

**This crate binds *who called*, not *what data was in the call*.** Prompt-body taint still requires the existing portcullis IFC machinery. SPIFFE lineage and IFC labels compose; they do not replace each other.

## Categorical framing (for the curious)

Per-call SPIFFE IDs lift the workload category to a bicategory where morphisms (calls) carry identities. Each child SVID's parent reference is a restriction map; the cocycle condition (gluing of sections across overlap) becomes verifiable from JWT signatures. This is the structure that makes end-to-end IFC sheaves measurable rather than only inferable. See `project_per_call_spiffe_lineage.md` in the project memory for the longer argument.

## License

MIT, same as the rest of nucleus.
