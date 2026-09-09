# Nucleus: Identity, Trust Federation, Delegation Carriers, Provenance — static read

Scope: the 21 crates named in the brief plus `portcullis::certificate` / `portcullis::escalation`,
`nucleus-node::pod_authority`, `nucleus-tool-proxy::{pod_cert,session_token,main}` (where the
identity/delegation crates are actually consumed), and docs/split-trust.md, docs/a2a-*.md,
docs/external-rp-integration.md, docs/wimse-aims-conformance-gap.md. Static reading only; no build.
All paths are relative to /home/user/nucleus.

Legend: **[IMPL]** implemented and wired on a live path; **[LIB]** implemented as a library but
not consumed by any runtime path; **[STUB/DOC]** documented or scaffolded only.

---

## 1. Inventory: what each crate actually is

| Crate | Status | One-line truth |
|---|---|---|
| `nucleus-identity` (18k LoC) | [IMPL]+[LIB] | SPIFFE `Identity` (`src/identity.rs:36`), self-signed CA + SPIRE client (`src/ca/`), Workload API server for VMs, mTLS verifier, software launch attestation (`src/attestation.rs:1-17`, explicitly *not* hardware rooted), assurance levels (`src/assurance.rs:34`). Also **library-only** pieces: `ApprovalBundle` JWS (`src/approval_bundle.rs`), DPoP RFC 9449 (`src/dpop.rs`), did:web + SPIFFE-DID binding (`src/did_binding.rs`), `CrossAgentReceipt` (`src/cross_agent.rs:89`, unsigned hash, "Proxy wiring (deferred)" at line 12). |
| `nucleus-spiffe-hail` (542) | [IMPL, internal/unstable] | Dial-by-SPIFFE-ID over iroh; peer proves SVID chain + `NodeBinding` (`src/lib.rs:55-62`, `authenticate_hail` line 149). ALPN/wire marked "INTERNAL / unstable" (line 29-31). |
| `nucleus-oidc-core` | [IMPL] | Provider-agnostic JWKS/JTI cache/`FederationRegistry`; inbound SPIFFE Federation bundle store with anti-rollback (`src/spiffe_federation.rs:287-460`). |
| `nucleus-oidc-provider` | [IMPL] | Workload OP: `/jwks.json`, discovery, `POST /oauth/token` RFC 8693 token exchange emitting `act` (`src/token.rs:329-344`, `src/issuer.rs:77-81`). Federation rules are `(subject_prefix, audience, allowed_grants, max_lifetime)` TOML (`src/federation.rs:46-58`). Key rotate/revoke on the verify-set (`src/keystore/mod.rs:23,131`). |
| `nucleus-github-oidc` / `nucleus-fly-oidc` | [IMPL] | External-IdP → SPIFFE-ID derivation with Lean-proved sanitizer (`nucleus-github-oidc/src/lib.rs:24-30`). RFC 7523 jwt-bearer exchange client behind a feature. |
| `nucleus-trust-registry` | [IMPL, MVP] | Non-custodial trust-domain→JWKS enrollment, GitHub-OIDC proof-of-control, witness-cosigned tlog; production path refuses bindings not in a cosigned STH (`src/lib.rs:37-48`). MVP trust base = single maintainer + single witness (lines 52-58). Proves GitHub-org control, **not** trust-domain ownership (lines 24-34). |
| `nucleus-agent-card` | [IMPL] | A2A v1.0 signed card (detached JWS over JCS) + `NucleusClaims` extension (`src/card.rs:645-678`); key must be resolved out-of-band (`src/lib.rs:44-53`); derives `nucleus_envelope::TrustAnchor`. `RuntimeGuaranteeProfile` is "attestation, not enforcement" (`src/card.rs:685-693`). |
| `nucleus-cred-broker` / `nucleus-cred-protocol` | [IMPL host half / STUB guest half] | CB4A PDP/CDP split enforced by dependency graph + `deny.toml`. `PodIdentity` is host-observed, non-deserializable (`cred-broker/src/lib.rs:47-67`). Crate doc says "Nothing is wired into nucleus-node yet" (line 39) — **stale**: `nucleus-node/src/broker.rs:29-41` says `pdp_decide`/`cdp_fetch` are on the live path, but "the GUEST half … has no vsock transport" and "`CredentialStore` is still constructed empty". |
| `nucleus-envelope` | [IMPL] | Portable provenance `Bundle` = payload + `Envelope{session_root, edges, jwks, checkpoints, merkle_anchor, meta}` (`src/bundle.rs:167-201`). `verify_bundle` (`src/verify.rs:512`) against out-of-band `TrustAnchor`; supports Merkle inclusion (`with_witness_pubkey`, line 188), k-of-n distinct-witness cosignature threshold (lines 207-220), payload binding (line 241), C2SP cosigs. **Crate-level doc (`src/lib.rs:29-45`) still says "inclusion proofs NOT in v1" — stale vs. code.** |
| `nucleus-receipt` (426) | [IMPL] | Ed25519 + BLAKE3 "colimit" receipt: `Session{session_id, issuer_kid, issued_at_micros, parent_chain: Vec<String>}` (`src/lib.rs:78-91`) + adjacently-tagged projections (`identity|capability|flow|economic|ci`, lines 102-118). JCS canonical signing bytes (line 210). Vendored into gatehouse (`/home/user/gatehouse/crates/gatehouse-types/src/lib.rs:8-10,457`). |
| `nucleus-witness` / `nucleus-witness-gossip` | [IMPL] | C2SP `tlog-witness` server (`/add-checkpoint`, `src/app.rs:29`), status matrix `server::decide` (line 88), redb persistence. Gossip layer: signed heads with **no embedded pubkey by design** (`witness-gossip/src/lib.rs:21-29`), iroh transport default-off. |
| `nucleus-lineage` (9.7k) | [IMPL] | Per-call SPIFFE ids (`src/id.rs:63`), signed hash-chained `LineageEdge`s (`verify_proof` `src/verify.rs:201-250`, `verify_strict`), STH/`TreeWitness`, Sigsum-style k-of-n `Policy` (`src/policy.rs:132,317`), MerkleProver. **Production JWT-SVID issuer: "No such impl ships in this repo today" (`src/issuer.rs:9-11`).** Shipped edge signers are `Pkcs8FileSigner` (file key) and the non-default `insecure-local-issuer`. |
| `nucleus-provenance` (499) | [IMPL, offline] | Fail-closed DSSE/in-toto artifact provenance at pod spawn against policy-listed Ed25519 keys. Sigstore keyless/Rekor/OCI pinning "out of scope" (`src/lib.rs:18-26`). |
| `nucleus-provenance-memory` | [IMPL] | Taint-labelled, recompute-verified, CRDT memory; k-of-n `SignedDeclassify` (`src/declassify.rs:67`); **`SignedTaskRef` Biscuit-style attenuation token** (`src/taskref_token.rs:1-60`). |
| `nucleus-verifier-service` | [IMPL] | Public `POST /v1/verify` running `verify_bundle` with caller-supplied JWKS; append-only SHA-256-chained verification log with signed STH + inclusion/consistency proofs (`src/app.rs:190-196`, `src/signing.rs`), witness peer federation ring. Credit endpoints bind identity = signer pubkey, no freshness ("replay-SAFE-by-idempotence, not replay-PREVENTED", `src/auth.rs:25-31`). |
| `nucleus-control-plane` (1k) | [IMPL, thin] | `execute_job` → signed pod-admit edge → runner → `BundleBuilder` → **self-check only** (`src/executor.rs:113`). |
| `nucleus-pca` (306) | [IMPL, dispatcher] | One `verify(AuthorizationToken, &VerifyCtx)` fanning to policy-cert / `verify_certificate` / IFC flow / isolation (`src/lib.rs:7-13`). Bundle + eval-receipt arms live in private crates (lines 17-26). |
| `nucleus-uniform-primitive` | [LEAN only] | 459-line Lean file, no Rust. Spine `preserves_seq` proven axiom-free; policy⇝ocap bridge proven; 3 named bridge axioms remain (ocap⇝ISA, ISA⇝kernel, kernel⇝hardware) (`lean/UniformPrimitive.lean:4-6,42-45,267,315`). |

---

## 2. Q1 — How does a principal's authorization get bound to an agent identity?

There are **three distinct carriers**, and the binding story differs for each:

### 2a. `LatticeCertificate` — the live delegation credential [IMPL]
`crates/portcullis/src/certificate.rs`. Biscuit-style chain: `AuthorityBlock{root_permissions, root_identity, not_after, signature, next_key, provenance}` (lines 115-137) + `DelegationBlock{effective_permissions, justification: MeetJustification, from_identity, to_identity, not_after, sink_scope, prev_block_hash, signature, next_key}` (lines 145-172) + final proof-of-possession signature (line 175-180). `verify_certificate` (lines 1344-1440): depth bound → root sig (`verify_ed25519_strict`) → per-block hash-chain, sig by previous holder's ephemeral key, `leq` monotonicity, `SinkScope` containment, expiry → PoP. Result is a sealed `VerifiedPermissions` that cannot be constructed outside the module (lines 185-215).

**Binding to identity happens at the node, not in the certificate.** `nucleus-node/src/pod_authority.rs:24-42`: (1) a registered pod is proved by its per-pod caller token or `ns/pods/sa/<uuid>` SVID and gets a one-hop child minted with the parent's holder key; (2) an **external mTLS caller** presenting `x-nucleus-delegation-cert` has its chain verified against `NUCLEUS_CERT_TRUST_ANCHORS`, **its leaf must equal the authenticated SPIFFE id** (`pod_authority.rs:~382`: `if verified.leaf_identity() != admission.caller_spiffe_id`), then the node *re-roots* (RFC 8693 `act` semantics, `provenance` = fingerprint of caller chain, `certificate.rs:126-136`); (3) one bootstrap identity (`--root-minter-spiffe-id`) may create from a bare policy; (4) everything else is refused. The guest side verifies the cert once at boot against `NUCLEUS_CERT_ROOT_PUBKEY` (never the embedded key) and builds the kernel from it (`nucleus-tool-proxy/src/pod_cert.rs:1-20`; `main.rs:1873 Kernel::from_certificate`). Request-borne certs are honoured **only** on the `SpiffeMtls` tier (`pod_cert.rs:23-37`).

Skeptical notes:
- The `from_identity`/`to_identity` strings in blocks are signed but `verify_certificate` never checks continuity (`block[i].from_identity == block[i-1].to_identity`) nor that any identity string is bound to an SVID; the chain is bound by **ephemeral keys**, and identity binding is only enforced at the leaf by the node/proxy (grep at `certificate.rs:151-153,984-998,1425`).
- Budget is *not* in the certificate; conservation is a node-side `BudgetLedger` (`pod_authority.rs:44-56`) and released allocations fold entirely into consumption — conservative, but a child's real spend is not reported back yet.
- Machine-checked: Kani harnesses `portcullis/src/kani/certificate_harnesses.rs:149-272` (attenuation-only, depth bound, over-budget refusal — with crypto stubbed); Lean `portcullis-core/lean/CertChainMonotoneExtracted.lean:146` (`chain_attenuates_monotone`, axiom audit at 167-169) over the Aeneas-extracted `certchain.rs`, bound to production by a parity test (`portcullis-core/src/certchain.rs:16-24`). Crypto, hash chain, expiry are **outside** the proof.

### 2b. `SignedTaskRef` — per-pod session capability token [IMPL, partially consumed]
`nucleus-provenance-memory/src/taskref_token.rs`. Chain of Ed25519 blocks with `parent_hash`, `verify_strict`, attenuation on operations + globbed paths via `DelegationScope::is_subset_of`. Node mints one per pod from the certificate's effective lattice (`nucleus-node/src/session_mint.rs:1-16`), injects `NUCLEUS_TASK_TOKEN{,_NONCE,_ISSUER}` on the boot channel; proxy verifies at startup fail-closed (`nucleus-tool-proxy/src/session_token.rs:1-22`) and consults `verified_scope()` in six handlers (`main.rs:2902,3064,3150,3335,3417,3612`). **Load-bearing caveat**: truncation resistance relies entirely on the host-pinned `expected_nonce` (`taskref_token.rs:40-60`); `allowed_paths` is deliberately empty ("Paths (deferred)", `session_mint.rs:35-41`).

### 2c. `SpiffeTraceChain` (escalation) — [LIB, weakly verified]
`portcullis/src/escalation.rs:76-91`: links carry `attestation: Vec<u8>` "e.g. signature from parent", but `verify()` (lines 257-270) checks only lattice monotonicity and expiry; `has_attestation` is a non-empty check (line 153). **No code anywhere verifies an attestation signature** (grep of `canonical_attestation_message` finds no consumer). The docstring promise "Revocation propagation (if any link is revoked…)" (line 177) has no implementation (no `revoked` field).

### 2d. Identity roots
Pods get X.509 SVIDs from `SelfSignedCa` or `SpireCaClient` via a Workload API server (`nucleus-identity/src/ca/mod.rs:1-16`, `workload_api.rs`). Launch attestation binds kernel/rootfs/config SHA-256s into the SVID but is **software-only, signed by the node** (`attestation.rs:10-18`). SPIFFE Federation inbound is real (`oidc-core/src/spiffe_federation.rs:399-460`); JWT-SVID minting for lineage has no production issuer in-repo (`lineage/src/issuer.rs:9-11`).

---

## 3. Q2 — Is there a delegation certificate/chain format?

Yes, but **three overlapping formats with different verification strength**:

1. `LatticeCertificate` (serde JSON via `to_bytes`, `certificate.rs:1228`; transported base64 as `AttenuationToken` in header `x-nucleus-delegation-cert` / env `NUCLEUS_POD_CERT`, `pod_authority.rs:79-88`). Fully signed, hash-chained, PoP, sealed verifier output, Kani+Lean on the monotone walk. **This is the real one.**
2. `SignedTaskRef` (JSON). Fully signed; ops-only scope today.
3. `SpiffeTraceChain` (serde). Structural only; attestation bytes unverified.
4. Receipt-level: `nucleus_receipt::Session.parent_chain: Vec<String>` (`receipt/src/lib.rs:88-91`) — bare SPIFFE strings, no per-hop signatures; the *receipt* is signed by one issuer kid, so the chain is an assertion by that issuer, not a verifiable delegation.
5. OIDC: RFC 8693 `act` nested actor claim (`oidc-provider/src/issuer.rs:77-81`) — for cross-org token exchange only.

There is **no single canonical delegation artifact** that spans all layers, and no conversion between them (e.g. a `LatticeCertificate` fingerprint does not appear in `Receipt.Session`, and `Session.parent_chain` is not derived from a verified cert). `nucleus-pca` unifies *verification dispatch* but not the carrier.

---

## 4. Q3 — How are approvals recorded and verified after the fact?

**Pre-flight (offline-verifiable) [IMPL]:** `ApprovalBundle` = ES256 JWS `typ: approval+jwt` with `{jti, iss (approver SPIFFE), iat, exp, manifest_hash, approved_operations, max_uses?, drand_round?, attestation_hash?, reason?}` (`nucleus-identity/src/approval_bundle.rs:111-159`). Tool-proxy loads one bundle from `NUCLEUS_APPROVAL_BUNDLE`, verifies against **pinned** `NUCLEUS_APPROVAL_TRUSTED_KEYS` (never the header JWK), fail-closed if none (`nucleus-tool-proxy/src/main.rs:803-836`), and populates `ApprovalRegistry` with `max_uses`/`exp` (lines 844-850). Verifiable after the fact by anyone holding the approver key + PodSpec bytes. Gaps: `verify()` itself does not enforce `max_uses` or JTI dedup ("caller responsible", line 10-11); `iss` is logged but never cross-checked against which trusted key signed (line 838-843 picks first key that verifies); `attestation_hash` and `drand_round` are carried but not checked in `verify()` (lines 359-467); a single bundle per pod (no multi-principal / quorum; `auth.rs:486-488` "a roster, not a quorum").

**Runtime (`POST /v1/approve`) [IMPL, weak record]:** requires drand-anchored Ed25519 approver signature at the auth layer, nonce replay cache, then `approvals.approve(op, count, exp)` and records a verdict with `actor: ActorIdentity::Unknown` (`main.rs:4319-4350`). So the after-the-fact record **does not name the approver**, and the record is a `VerdictSink` entry — the concrete sink is tracing spans/OTLP + lockdown flags (`nucleus-tool-proxy/src/verdict_sink.rs:1-8`), not a signed lineage edge. There is **no `EdgeKind` for approval/delegation** in `nucleus-lineage/src/edge.rs:287-420` (kinds: PodAdmit, ToolCall, LlmCall, ArtifactProduced, Merge, DocumentRetrieved, economic kinds, Other). Comment at `main.rs:3110-3122` documents a known routing hole (#2406: a `/v1/approve` grant never reaches the registry when `http_kernel_decide` returns `requires_approval` from mediation) and a double-consume.

**Declassification approvals [IMPL, lib]:** k-of-n `SignedDeclassify` witnesses in provenance-memory (`declassify.rs:67-90`), domain-tagged, `verify_strict`.

---

## 5. Q4 — Are receipts / witness chains complete and tamper-evident?

**Tamper-evident: yes, at three layers** — per-edge Ed25519 over `canonical_edge_bytes(edge, prev_hash)` + hash chain (`lineage/src/verify.rs:201-262`; JWK validity windows honoured, line 239-241); Merkle STH + per-edge inclusion proofs (`envelope/src/verify.rs:337-355`); k-of-n **distinct** trusted-witness cosignatures (lines 193-220, 356-360) with C2SP note framing (`lineage/src/signed_note.rs`), a C2SP witness server enforcing consistency/no-rollback (`nucleus-witness/src/lib.rs:7-15`), gossip that cannot smuggle keys. Verifier-service keeps its own signed, inclusion-provable log. This is well engineered and the docs are honest (`docs/split-trust.md:327-404`).

**Complete: no, in four senses.**
1. *Completeness of mediation into lineage* is not proven: edges exist for tool/LLM/artifact calls but there is no edge for delegation hops, approvals, certificate re-rooting, or credential-broker actions; absence of an edge proves nothing (acknowledged in `docs/a2a-receipt-extension.md:142-160`).
2. *Signer provenance*: production edge signers are a PKCS#8 file key or an insecure local issuer; no SPIRE/Workload-API-backed `EdgeSigner` ships (`lineage/src/issuer.rs:9-11`). `control-plane::execute_job` self-checks only (`executor.rs:113`).
3. *STH is a time attestation unless the verifier opts in*: without `with_witness_pubkey`, `verify_bundle` ignores the Merkle anchor's meaning (`verify.rs:229,337-342`); C2SP cosigs are "silently uncountable" without `c2sp_origin` (line 247-262).
4. *Receipt ≠ delegation proof*: `nucleus-receipt` signs whatever projection JSON the issuer put in; `Projection::Identity` is untyped `serde_json::Value` (`receipt/src/lib.rs:104`); `agent-card::envelope` explicitly says the projection "carries what a verified card claimed, not the proof that anyone verified it" (`agent-card/src/envelope.rs:27-35`).

Revocation: none for `LatticeCertificate`, `SignedTaskRef`, approval bundles or lineage keys beyond expiry/JWKS validity windows; X.509 paths explicitly skip CRL/OCSP (`nucleus-identity/src/verifier.rs:319`, `tls.rs:319`, `did_builder.rs:374`). Only the OIDC keystore has `revoke(kid)` (`oidc-provider/src/keystore/mod.rs:131`).

---

## 6. Q5 — Cross-org / cross-host delegation

- **Cross-host, same operator [IMPL]:** external mTLS caller → `x-nucleus-delegation-cert` verified against `NUCLEUS_CERT_TRUST_ANCHORS` → leaf == caller SVID → re-root with `provenance` (`pod_authority.rs:31-38`). k-of-n witnesses across failure domains (`docs/split-trust.md:69-160`). `nucleus-spiffe-hail` for dial-by-SPIFFE-ID (unstable wire).
- **Cross-trust-domain identity [IMPL]:** SPIFFE Federation bundle ingestion with anti-rollback (`oidc-core/src/spiffe_federation.rs`), trust-registry enrollment (GitHub-OIDC proof, cosigned tlog), OP token exchange with `act` and per-(subject-prefix, audience) rules (`oidc-provider/src/federation.rs:46-58`), external RP pattern (`docs/external-rp-integration.md`).
- **Cross-org *capability* delegation [PARTIAL]:** a foreign org's `LatticeCertificate` is accepted only if its root key is in the node's static anchor list; there is no mapping from a federated SPIFFE trust bundle or trust-registry enrollment to certificate trust anchors — identity federation and capability federation are separate systems with separate roots. `CrossAgentReceipt` for agent-to-agent IFC joins is unsigned and unwired (`cross_agent.rs:12-16,192`). A2A receipts bind bytes to a verified caller SPIFFE id but not transport or delivery (`docs/a2a-receipt-extension.md:142-160`).
- Trust-registry MVP: single maintainer + single witness; proves GitHub-org control not domain ownership (`trust-registry/src/lib.rs:24-58`).

---

## 7. North-Star clause scoring (identity/provenance slice)

| Clause | Assessment |
|---|---|
| (1) any model | Good. Vendor-neutral by construction (`oidc-core`, `control-plane::JobRunner`). Two leaks: `nucleus-github-oidc/src/token_exchange.rs:7` names "Anthropic's Claude API WIF"; `docs/external-rp-integration.md:~113` cites `project_spiffe_wif_anthropic`. `nucleus-node/src/trust_gate.rs:38,354-442` hard-codes `trust.coproduct.one` label keys (observational only). |
| (2) breadth/low friction | Credential broker guest half missing and store empty (`node/src/broker.rs:36-41`); path scoping of task tokens deferred; request-borne delegation only on the mTLS tier. |
| (3) expressiveness of authorization | Strong: lattice meet + sink scope + expiry + depth + budget ledger; `act` on OIDC; k-of-n declassify. Weak: no revocation anywhere except OIDC keys; approvals are single-approver roster, not quorum; no multi-principal co-authorization; approval bundle `max_uses` enforced only by proxy registry. |
| (4) structurally incapable | Best part of the slice: sealed `VerifiedPermissions`, `verify_strict` everywhere, pinned anchors, host-only nonce, `PodIdentity` non-deserializable, dependency-graph PDP/CDP split. Holes: `SpiffeTraceChain` attestation unverified; runtime approvals recorded with `ActorIdentity::Unknown`; #2406 routing gap; certificate identity continuity unchecked; software-only attestation root. Proof coverage is real but narrow (monotone walk, DEL1/DEL2, uniform-primitive spine with 3 axioms). |
| (5) continuously expand | No metric ties this slice to "delegatable envelope growth". Ratchets exist only as axiom-count baselines (`nucleus-uniform-primitive/lean/.uniform-primitive-axiom-baseline`) and CI pins; `docs/wimse-aims-conformance-gap.md` (2026-05-28) is stale — GAP-6 `act` and GAP-10 `to_wimse_uri` are now implemented (`oidc-provider/src/issuer.rs:77`, `lineage/src/id.rs:301-320`). |

## 8. Top weaknesses (ranked)
1. Runtime approvals lose the approver identity (`tool-proxy/src/main.rs:4344 ActorIdentity::Unknown`) and are not emitted as signed lineage edges; no `EdgeKind` for approval/delegation (`lineage/src/edge.rs:287-420`).
2. `SpiffeTraceChain.attestation` is never cryptographically verified (`portcullis/src/escalation.rs:153,257-270`); "revocation propagation" is doc-only (line 177).
3. No revocation for `LatticeCertificate`/`SignedTaskRef`/approval bundles; X.509 revocation explicitly skipped (`nucleus-identity/src/verifier.rs:319`, `tls.rs:319`).
4. No production JWT-SVID/edge signer backed by SPIRE (`lineage/src/issuer.rs:9-11`); attestation root is node-software-only (`nucleus-identity/src/attestation.rs:10-18`).
5. Fragmented delegation carriers: certificate ↔ task token ↔ receipt `parent_chain` ↔ OIDC `act` are not linked; capability trust anchors are a static key list separate from SPIFFE federation/trust-registry (`pod_authority.rs:104-108`).
6. Stale docs that overstate or understate: `envelope/src/lib.rs:29-45` ("inclusion proofs NOT in v1"), `cred-broker/src/lib.rs:39` ("nothing wired"), `wimse-aims-conformance-gap.md` GAP-6/10, `external-rp-integration.md` "zero gaps".
