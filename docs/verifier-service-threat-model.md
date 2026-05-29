# nucleus-verifier-service — Threat Model

**Status:** Living document. Owners: nucleus security team.
**Last updated:** 2026-05-29.
**Scope:** the public `verifier.coproduct.io` deployment and the
in-process verifier libraries (JS + Python SDKs).
**Audience:** buyer security teams, external auditors, internal review.

This is a STRIDE-style threat model. For each identified threat we
document the scenario, the mitigation that ships today (anchored to
source lines so an auditor can spot-check), the residual risk, and
any open work.

The cross-cutting hardening from the
[pre-ship OIDC OP audit](./oidc-provider-audit-v1.md) (zero CRIT,
five HIGH closed, seven MED closed, five LOW closed) extends to the
verifier service by composition — the same hand-rolled JWS, the
same algorithm allowlist, the same constant-time error oracles.

---

## Asset inventory

| Asset | Sensitivity | Where it lives |
|---|---|---|
| The verifier service's Ed25519 STH signing key | **High** | Fly.io secret `NUCLEUS_VERIFIER_SIGNING_KEY` (env-injected at boot) |
| The persistent SQLite database (`verifications` + `log_entries`) | **Medium** — public hashes; archived payloads | Fly volume mount at `/data/verifier.db` |
| The published verifying key (JWKS) | **Public by design** | `GET /.well-known/jwks.json` |
| Verification request payloads (bundles + trust anchors) | **Variable** — caller controls | Transient + optionally archived in `verifications.payload_size_bytes` only (the bytes themselves are NOT archived in v1) |
| The signed tree head | **Public by design** | `GET /v1/log/sth` |
| Operator audit logs | **Medium** | structured `tracing` to stderr → Fly log shipper |

## Trust boundaries

1. **Public internet ⇄ Fly edge.** TLS terminated at the Fly edge
   (HTTPS, `force_https = true`). Everything inside the boundary is
   already authenticated as "the caller's bytes."
2. **Fly edge ⇄ verifier-service process.** Plain TCP on internal
   network. The service trusts the connecting peer IP for rate
   limiting (`tower-governor`'s `PeerIpKeyExtractor`).
3. **Service process ⇄ SQLite volume.** Volume is single-machine,
   single-writer. No network layer to defend.
4. **Service process ⇄ STH signing key.** The key is in process
   memory after boot; `Debug for VerifierSigner` deliberately
   redacts the secret bytes (`signing.rs:42`).
5. **Verifier-service ⇄ in-process SDK callers (JS / Python).**
   No trust boundary — SDK callers run the same Rust verifier
   compiled to wasm/PyO3.

## STRIDE summary

| Threat ID | STRIDE | Title | Status |
|---|---|---|---|
| T1 | Tampering | Forged bundle (single-edge signature swap) | **Mitigated** |
| T2 | Tampering | Stale signed tree head (replay) | **Partially mitigated** — iter-3 (#95) adds consistency proofs |
| T3 | Spoofing | Witness collusion against the federation | **Mitigated** via cosignature threshold |
| T4 | Information Disclosure / DoS | Verifier-service compromise | **Mitigated by design** — SDKs make us non-critical |
| T5 | Repudiation | EU AI Act marking bypass via downgrade | **Mitigated** |
| T6 | DoS | Computational DoS on `POST /v1/verify` | **Mitigated** |
| T7 | Tampering | Replay of long-expired bundles | **Mitigated** |
| T8 | Spoofing | Unauthorized job submission to control-plane | **Mitigated** via SPIFFE JWT-SVID (#79) |

---

## T1 — Forged bundle (Tampering)

**Scenario.** Attacker controls a producer-published bundle and
flips one byte of the payload, one byte of a lineage edge, or one
edge's signature, hoping the verifier accepts it.

**Mitigation (shipped).** Every edge carries an Ed25519 proof over
`canonical_edge_bytes(edge, prev_hash)`. The verifier replays the
chain in order; any mutation breaks the signature (the
attacker doesn't possess the producer's signing key) AND the chain
hash (`prev_hash` covers the previous edge's content hash). Three
load-bearing checks:

- Per-edge proof: `nucleus-envelope/src/verify.rs` walks `edges`
  in order, verifies against `trust_jwks` (NOT the embedded JWKS —
  the embedded JWKS is producer-controlled and gets explicitly
  ignored when an out-of-band anchor is supplied).
- Chain integrity: each edge's `prev_hash` MUST match the
  preceding edge's `edge_content_hash`. Splicing breaks chain.
- JWS algorithm allowlist: `header.alg` MUST equal `"EdDSA"` —
  hand-rolled JWS parser refuses `alg=none` (OIDC OP audit HIGH-5).

**Residual risk.** The trust JWKS is producer-published; an
attacker who compromises the producer's signing key has full
forgery capability. Out of scope for the verifier (defended at the
producer / OIDC OP layer via short JWT-SVID lifetimes + key
rotation).

**Open work.** None — closed by the v1 audit cycle.

---

## T2 — Stale signed tree head (Tampering)

**Scenario.** Verifier-service signs an STH at `tree_size=5`. Six
months later, the operator rolls the log back to size 5 and
re-signs an STH that claims state at the new "current" time. A
downstream consumer who cached the size-5 STH from the original
time can't tell the difference.

**Mitigation (iter-2 — shipped).** The STH is Ed25519-signed by
the verifier's published key. A consumer can verify the signature
against the JWKS at `/.well-known/jwks.json` and confirm
authenticity of the operator's claim.

**Mitigation gap.** What v1 of the STH does NOT yet provide:
**consistency proofs** between two STHs. Without those, the
verifier-service operator can in principle reset state — a
consumer who only ever sees one STH at a time can't detect the
rollback.

**Residual risk.** A single-operator log without consistency
proofs is descriptively trustworthy (you can verify it signed an
STH) but not auditable for non-monotonicity.

**Open work.** Task #95 (RFC 9162 Merkle + inclusion +
consistency proofs) closes this gap. Until landed, buyers
requiring auditable monotonicity should pin specific STHs via
their own caching layer or wait for iter-3.

---

## T3 — Witness collusion (Spoofing)

**Scenario.** A single witness operator gets compromised. Their
cosignature on a malicious STH would have appeared trustworthy
to any verifier configured to trust them.

**Mitigation (shipped).** `nucleus-envelope` supports a
**cosignature threshold** (v2.1 federation): the verifier
configuration specifies a set of trusted witnesses + a minimum
count required to accept the STH. As long as the threshold
exceeds the largest collusion attacker can field, the federation
holds.

For bundle verification:
- `TrustAnchor::with_trusted_witness(pubkey)` registers each
  trusted witness key.
- `TrustAnchor::cosignature_threshold(N)` sets the minimum.
- `nucleus-envelope/src/verify.rs` counts distinct verifying
  signatures and rejects below threshold with
  `InsufficientCosignatures{verified, required}`.

For the verifier-service log itself: cross-witness gossip
(task #73) is the analog at the verifier layer — not yet shipped.

**Residual risk.** A buyer who configures `threshold=1` against a
single witness has zero collusion defense; this is operator
posture, not a verifier-service flaw.

**Open work.** #73 witness gossip for the verifier-service log.

---

## T4 — Verifier-service compromise (Information Disclosure / DoS)

**Scenario.** The hosted `verifier.coproduct.io` machine gets
rooted or the operator goes rogue. What's the blast radius?

**Mitigation by design.** **The verifier-service is convenience,
not the trust root.** Two SDKs (JS via wasm-pack at
`sdks/verifier-js`; Python via PyO3 at `sdks/verifier-py`) compile
the same Rust verifier and run it in the customer's own process.
A compromised hosted verifier cannot:

- Lie about a bundle's validity to a customer running the SDK.
- Forge a bundle (it doesn't hold producer signing keys).
- Forge a Merkle inclusion proof against a witness-signed STH
  (the witness key is held by the producer / federation, not us).

What a compromised verifier CAN do:

- Lie to a customer who chose not to use the SDK ("this bundle is
  valid" when it isn't). Mitigated by aggressive promotion of
  SDK-side verification in product copy + integration guides.
- Refuse service. Standard DoS, defended by the same controls as
  T6.
- Tamper with the persisted `verifications` table to misrepresent
  history of submissions. Mitigated by SQL transaction integrity
  + future cross-verifier gossip (#73).

**Residual risk.** Customers who don't run the SDK + don't
cross-check with another verifier are trusting us. We document
this prominently.

**Open work.** SDK adoption metrics + #88 audit charter
(quarterly published audits) build trust in the hosted endpoint;
#73 witness gossip closes the persistent-state tampering vector.

---

## T5 — EU AI Act marking bypass (Repudiation)

**Scenario.** A producer claims to mark their AI-generated content
per EU AI Act Article 50 by attaching a nucleus bundle, but the
marking is structurally weaker than the regulation requires (e.g.
the envelope is empty + verifier is in self-check mode).

**Mitigation (shipped).** The bundle's `meta.schema_version` and
the report's `trust_mode` are first-class fields a verifier
returns to the caller. A downstream auditor presented with
`{"trust_mode": "self_check_only"}` MUST reject the bundle as a
provenance claim. This is documented in
[the Article 50 mapping doc](./eu-ai-act-article-50.md) and
echoed in the bundle struct's rustdoc.

**Residual risk.** The verifier surfaces the posture; the
downstream consumer must act on it. A regulator-facing pipeline
that doesn't read `trust_mode` is structurally non-compliant.

**Open work.** The compliance posture doc
([compliance-posture.md](./compliance-posture.md)) gives buyers
explicit downgrade-detection checklists they can run before
accepting a producer's bundles.

---

## T6 — Computational DoS on `POST /v1/verify` (DoS)

**Scenario.** Attacker sends a high rate of large bundles. Each
bundle can trigger up to `MAX_ENVELOPE_EDGES = 10_000` Ed25519
verifies + Merkle audit-path validation. The cost of a single
adversarial bundle is bounded but real; the concern is
sustaining a flood that exhausts worker threads.

**Mitigation (shipped — defense in depth):**

1. **`RequestBodyLimitLayer`**: 2 MiB cap on request bodies
   (`app.rs:46`). Pathological multi-MB payloads rejected at the
   tower layer before they reach the handler.
2. **`ConcurrencyLimitLayer`**: 256 in-flight requests across the
   service (`app.rs:28-35`). Excess requests queue at the tower
   layer; combined with the 30s timeout this bounds total worker
   occupancy.
3. **`tower-governor` per-IP token bucket** (#70): burst capacity
   60, replenish 1/sec sustained. A single hostile IP can fire 60
   requests immediately then is throttled. `app.rs:` with-rate-limit
   wrapper, applied in `main.rs` via `into_make_service_with_connect_info`.
4. **`TimeoutLayer`**: 30s per-request budget kills runaway work.
5. **`MAX_ENVELOPE_EDGES = 10_000`** in nucleus-envelope itself
   caps the per-request signature-verify count.
6. **`MAX_COSIGNATURES_PER_STH = 64`** caps the cosig-verify count.
7. **`MAX_TRUSTED_WITNESSES_PER_REQUEST = 32`**: caller-supplied
   trusted-witness list bounded at the route layer (audit HIGH-1
   fix in `nucleus-verifier-service/src/routes.rs:18`).

**Residual risk.** Distributed attacks across many IPs bypass the
per-IP limiter. Operators must front-line with an edge WAF
(Cloudflare, etc.) — documented in the operator notes
(`app.rs:80-90`).

**Open work.** None for the v1 hosted service. Bundle-metrics
(#91) gives operators a load-saturation dashboard.

---

## T7 — Replay of long-expired bundles (Tampering)

**Scenario.** Attacker presents an old, otherwise-valid bundle
months after the agent session ended.

**Mitigation (shipped — at the producer / OIDC OP layer):**

- The OP's `JtiCache` (`nucleus-oidc-core/src/jti_cache.rs`)
  rejects replays of any JWT it minted, within the JTI retention
  window (max 1 hour per OIDC OP audit HIGH-1).
- Bundle envelopes carry signed tree heads (STHs) with timestamps;
  a verifier can refuse bundles whose STHs are older than a
  caller-configured `max_age_ms`.
- The bundle's `envelope.meta.created_at` is a wall-clock timestamp
  the producer self-attests; not authoritative against a malicious
  producer but useful for honest-replay rejection.

**Residual risk.** The verifier doesn't itself enforce a maximum
bundle age — that's caller policy. Documented in the integration
guide (#85).

**Open work.** None — the layered defenses cover the threat.

---

## T8 — Unauthorized job submission (Spoofing)

**Scenario.** An unauthenticated client posts a job to the
control-plane-server, hoping to consume compute / produce a fake
bundle attributed to a victim tenant.

**Mitigation (shipped — #79):** the control-plane-server requires
SPIFFE JWT-SVID Bearer authentication on all four protected
routes (`submit_job`, `get_job`, `get_bundle`, `stream_job_events`).
The verifier middleware:
- enforces alg=EdDSA only (rejects `alg=none` / RS256 etc.)
- looks up `kid` in the configured trust JWKS — unknown kids
  rejected as 401
- enforces `aud` matches the configured allowed audience
- enforces `sub` starts with the configured SPIFFE prefix
  (e.g. `spiffe://<td>/ns/agents/sa/`) — mismatch is 403
- enforces `exp + 60s_skew > now` — expired tokens rejected as 401

`healthz` remains public for liveness probes.

**Residual risk.** An operator who runs the control plane with
SPIFFE auth disabled (development mode) has no defense — by
design. The boot path logs a loud warning. Partial config
(1 or 2 of 3 SPIFFE flags) is rejected at boot via
`SpiffeConfigError::Partial { set_count }` (#96).

**Open work.** None — closed by #79 + #96.

---

## Audit cadence

- **Quarterly** skeptical-code-auditor passes on
  `nucleus-envelope`, `nucleus-verifier-service`,
  `nucleus-control-plane-server`, and `nucleus-oidc-provider`.
  Verdicts published in `docs/audits/`.
- **Biennial** cryptographic-protocol review by external auditors
  (target: Trail of Bits, NCC Group, or Cure53).
- **Continuous** adversarial-bundle corpus run in CI on every PR
  touching the envelope crate (#89 — landed alongside this
  document).

See [audit-charter.md](./audit-charter.md) for the public
commitment, planned auditor selection, and disclosure policy.

## Disclosure policy

Security issues: `security@coproduct.io` (also published in
`/.well-known/nucleus-verifier-configuration`). 90-day
coordinated disclosure window from acknowledgement, accelerated
to 14 days for actively-exploited vulnerabilities.

## What this doc is NOT

- A penetration test report. We commit to commissioning the first
  external pen-test no later than 60 days before the EU AI Act
  Article 50 effective date.
- A safety case for the customer's AI agent itself. The verifier
  service verifies the provenance chain; what the agent did inside
  the chain is the customer's responsibility to audit via the
  lineage records.
- Legal advice. Compliance posture (#87) maps controls to
  framework requirements but is not a legal opinion.
