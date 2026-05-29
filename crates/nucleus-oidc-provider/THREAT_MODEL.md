# nucleus-oidc-provider — Threat Model (v1.0)

**Date:** 2026-05-28
**Scope:** The OIDC OP service that mints JWT-SVIDs / OIDC tokens for nucleus pods and exchanges externally-issued SVIDs for audience-bound tokens (RFC 8693).
**Status:** Pre-implementation. Mitigations name the implementing task IDs (#28-#56) from the OIDC scoping DAG.
**Reviewers:** Auditor should re-read this document before any change to: token endpoint, key-store, JWKS endpoint, federation-rule schema, or SPIRE bundle handling.

---

## 1. Document conventions

- **RP A**, **RP B** — distinct external Relying Parties. We name no real vendors.
- **OP** — this service (nucleus-oidc-provider).
- **SVID** — SPIFFE Verifiable Identity Document. When unqualified, JWT-SVID.
- **Subject token** — an SVID presented *to* the OP at the token endpoint.
- **Issued token** — an OIDC token *minted by* the OP and returned to the caller.
- Likelihood scale: **L**ow / **M**edium / **H**igh — calibrated against motivated attackers, not opportunistic.
- Impact scale: **C**onfidentiality / **I**ntegrity / **A**vailability / **A**uditability.

## 2. Asset inventory

| Asset | Description | Sensitivity |
|---|---|---|
| **Active signing key** | The current Ed25519 private key used to sign issued tokens. | **CRITICAL.** Compromise = mesh-wide identity forgery. |
| **Verify-set (JWKS)** | All public keys currently in the grace window. | Public; integrity matters. |
| **Federation rule registry** | `(subject_prefix, audience, allowed_grants, max_lifetime)` table. | Sensitive — misconfig = privilege escalation. |
| **SPIRE trust bundle** | Public keys SPIRE uses for X.509 + JWT-SVIDs. | Public; integrity-critical. |
| **JtiCache** | Replay-window cache of seen `jti` values. | Volatile but security-critical. |
| **Issuer URL** | The OP's external identity. | Public; bound into every issued token. |
| **Discovery document** | RFC 8414 metadata at `/.well-known/openid-configuration`. | Public; integrity-critical. |
| **Token endpoint logs** | Per-exchange audit trail. | Confidential — contains subject identifiers. |

## 3. Trust boundaries

```
┌─────────────┐    Boundary 1: Untrusted Internet
│  RP / Caller│ ──────────────────────────────────────►
└─────────────┘
       │
       ▼  (HTTPS, mTLS optional)
┌─────────────────────────────────────────────┐
│  nucleus-oidc-provider                      │
│   • Token endpoint                          │
│   • JWKS endpoint                           │
│   • Discovery endpoint                      │
└──────────┬──────────────────┬───────────────┘
           │ Boundary 2:      │ Boundary 3:
           │ Unix socket      │ Filesystem / KMS
           ▼                  ▼
   ┌──────────────┐    ┌──────────────┐
   │ SPIRE Agent  │    │ JwtKeyStore  │
   └──────────────┘    └──────────────┘
```

- **Boundary 1** (RP ↔ OP): all inbound RPs are untrusted until their subject_token verifies + federation rule matches.
- **Boundary 2** (OP ↔ SPIRE Agent): co-located on the same node, communication via the UNIX domain socket exposed by the SPIRE Workload API. Trust assumption: kernel namespace isolation.
- **Boundary 3** (OP ↔ KeyStore): filesystem (FileKeyStore) or external KMS. Operator's responsibility to enforce ACLs / IAM.

## 4. Threat catalog

### T01 — Signing-key compromise

**Description.** Active Ed25519 private key is exfiltrated from the FileKeyStore (or the in-memory process address space).

**Attack scenario.** Attacker gains node-local read access to the encrypted KeyStore blob. They also obtain the passphrase via separate credential theft (operator laptop, CI secret). They decrypt the blob, lift the active key, and sign forged tokens claiming any `sub` and any `aud` permitted by the federation rules. RP A accepts these as if from a real nucleus pod.

**Impact.** C, I, A**a** — total identity forgery within the OP's authority. Affects every RP that trusts the OP's JWKS.

**Likelihood.** Low for the pure crypto path; Medium when including operator-credential compromise.

**Mitigation.**
- Encrypted-at-rest KeyStore with passphrase or KMS unwrap (#33).
- Zeroize private key on Drop (#33, #34).
- Mandatory rotation primitive with grace window (#37) bounds the post-compromise blast radius to one rotation period.
- KID = RFC 7638 thumbprint (#33) so a stolen key cannot be re-published under a different KID without detection.
- Key-rotation property tests (#52) ensure rotation never accepts the compromised key after `not_after`.

**Residual risk.** Medium. Attacker who exfiltrates *and* publishes a compromised key faster than the operator rotates it can forge tokens for the rotation period. Detection relies on out-of-band JWKS monitoring (operator responsibility).

**Refs.** RFC 8725 §3.5, RFC 7517 §6.

---

### T02 — JWKS endpoint poisoning

**Description.** Adversary serves a JWKS that includes their own key alongside (or in place of) the OP's real keys. RPs that fetched the poisoned JWKS will accept tokens signed by the attacker.

**Attack scenario.** Attacker MitM's the JWKS endpoint (DNS hijack, BGP rerouting, or compromised CDN edge) and replaces the body with a JWKS containing an attacker-controlled Ed25519 public key. RP A's JWKS cache (TTL 5 min per `Cache-Control: max-age=300`) absorbs it and trusts attacker-signed tokens for the cache lifetime.

**Impact.** C, I, A**a** — for the cache lifetime, attacker holds the OP's identity at every RP that fetched during the poisoning window.

**Likelihood.** Low at the OP itself (HTTPS + cert pinning by the operator), Medium when including upstream CDN or DNS compromise.

**Mitigation.**
- HTTPS-only serving with strict transport security headers (#43).
- `ETag` derived from key-set content hash (#35) — RPs that store and compare etags detect substitution.
- Recommend RPs use JWKS pinning (documented in operator runbook, #53).
- Discovery doc (#36) references jwks_uri with the canonical issuer URL — RP must verify host match.

**Residual risk.** Medium. Most RPs do not pin JWKS thumbprints. Defense relies on TLS + CDN integrity. We surface the risk in the operator runbook.

**Refs.** RFC 7517 §5, RFC 8414 §3.

---

### T03 — Replay across audiences

**Description.** A token issued for `aud = RP A` is presented to `aud = RP B`, or the same token is re-presented to RP A multiple times.

**Attack scenario.** Attacker intercepts an issued token bound to RP A (via compromised RP A logs, a misbehaving proxy, or browser history). They replay it to RP B, hoping RP B does not strictly check `aud`. Or they replay it to RP A within the token's exp window for actions they were not authorized to perform.

**Impact.** C, I, A**a** — depends on RP B's permission set.

**Likelihood.** Medium. Many RPs in the wild are lax about `aud` and `jti` enforcement (per the OH-MY-DC research on OIDC CI/CD misconfigurations, Unit 42).

**Mitigation.**
- Mandatory `aud` claim on every issued token, single-valued (#34).
- `jti` cache rejects replay within token lifetime (#42).
- Token lifetime cap 1h (#34) bounds the replay window even when `jti` cache is bypassed (e.g., RP A doesn't check `jti`).
- Documented in operator runbook: RPs MUST validate `aud` exactly and SHOULD validate `jti`.

**Residual risk.** Low at the OP. Replay defense at the RP is outside our control; we mitigate to the extent of issuing single-audience, time-bounded, `jti`-tagged tokens.

**Refs.** RFC 8725 §3.9 (audience validation), §3.12 (cross-JWT confusion), RFC 7519 §4.1.7 (jti).

---

### T04 — Algorithm downgrade / confusion

**Description.** Attacker forces the OP or an RP into accepting a JWT signed with a weaker or asymmetric-misused algorithm (`alg=none`, HS256 with the public key as secret, RS256→HS256 confusion).

**Attack scenario.** Attacker submits a subject_token with `alg=none` and no signature, hoping the OP's JWT parser accepts unsigned tokens. Alternatively, attacker takes the OP's published Ed25519 public key, encodes it as a string, and uses it as an HMAC secret to sign a forged token claiming `alg=HS256` and `kid=<op-kid>`. A naive verifier looks up the key by KID, gets an Ed25519 public key, and tries to use it for HMAC verification — succeeding.

**Impact.** I, A**a** — token forgery.

**Likelihood.** Medium — these are the most-exploited JWT bugs in the wild.

**Mitigation.**
- Algorithm-pinned construction in JwtIssuer (#34): constructor rejects HS\*, RS\*, none, ES\*, leaves only EdDSA.
- Algorithm-pinned verification: every verify path takes the expected `alg` as input, not from the token header.
- CI gate (#54) static-checks every source path under `crates/nucleus-oidc-{provider,core}/` for accidental `alg=none`/HS\*/RS\* references outside explicit-reject negative-test fixtures.
- JWKS endpoint advertises only Ed25519/OKP keys (#35).
- Discovery doc advertises `id_token_signing_alg_values_supported = ["EdDSA"]` exclusively (#36).
- Fuzz harness (#51) tests subject_token validator against malformed `alg` headers.

**Residual risk.** Very Low at the OP. RP-side downgrade is outside scope; operator runbook documents.

**Refs.** RFC 8725 §3.1, §3.2, §3.3.

---

### T05 — Federation-rule misconfiguration

**Description.** An overly-permissive federation rule allows a low-privilege pod to obtain a token for a high-privilege RP audience.

**Attack scenario.** Operator misconfigures a rule: `subject_prefix = "spiffe://nucleus/ns/*"` (instead of `"spiffe://nucleus/ns/production/*"`) and `audience = "https://kms.rp-a.example/admin"`. Any pod in any namespace can now exchange its SVID for a token bound to the admin API of RP A. The Palo Alto OH-MY-DC research catalogs this exact failure class across CI/CD OIDC providers in the wild.

**Impact.** C, I, A**a** — privilege escalation across compartments.

**Likelihood.** High — this is the dominant failure mode for OIDC federation in production.

**Mitigation.**
- Rule schema uses `#[serde(deny_unknown_fields)]` (#41) — typos in field names fail-loud, not silent-ignore.
- Glob matching limited to `*` *suffix* on subject_prefix (#41); no full regex (prevents both ReDoS and overly-permissive patterns).
- Default-deny: no matching rule → 403 (#41).
- Bounded rule count (default 1024) prevents config-DoS (#41).
- Audit-log each Deny with the matched-rule-id or "no rule matched" (#41), enabling diff-based config review.
- Operator runbook (#53) mandates least-privilege subject_prefix per audience.
- Real-world validation (#56) against an actual external RP exercises the rule path end-to-end.

**Residual risk.** Medium. Rule correctness is intrinsically operator-dependent. We provide tooling but cannot prove the operator's intent matches their config.

**Refs.** Unit 42 *OH-MY-DC: OIDC Misconfigurations in CI/CD*; NIST SP 800-63C §5.

---

### T06 — Clock-skew amplification

**Description.** Clock skew between the OP and an RP (or between SPIRE Agent and OP) causes either (a) valid tokens to be rejected (availability hit) or (b) expired tokens to be accepted (security hit).

**Attack scenario.** Attacker exploits NTP poisoning to push the OP's clock backwards by 30s. Tokens issued during the skew window claim `iat` values 30s in the past; an RP correctly enforcing `iat <= now + small_leeway` accepts them. Replay window effectively extends by the skew.

**Impact.** A, A**a** — degraded replay defense.

**Likelihood.** Low (NTP poisoning is hard); Medium for accidental skew (VM clock drift, container time-source bugs).

**Mitigation.**
- Token lifetime hard-capped 1h (#34) — bounds the worst-case effective replay window.
- Mandatory `iat`, `exp`, optional `nbf` (#34); `nbf` SHOULD be set to `iat - leeway` only by explicit caller opt-in.
- OP refuses to start if clock skew vs SPIRE bundle is > 60s (#45 — graceful degradation).
- Health endpoint reports clock-drift status (#43).
- Operator runbook (#53) requires chrony/ntpd on the host with monitored drift.

**Residual risk.** Low.

**Refs.** RFC 7519 §4.1.4, §4.1.5, §4.1.6.

---

### T07 — Token endpoint DoS

**Description.** Attacker floods the token endpoint to exhaust signing-key throughput, JtiCache capacity, or thread pool.

**Attack scenario.** Attacker sends 10k/s requests each carrying a malformed subject_token, forcing the OP into 10k/s JWT parse + signature attempts + jti lookups + federation matches. Worker threads saturate, legitimate traffic 5xx's.

**Impact.** A.

**Likelihood.** High — public endpoints attract abuse.

**Mitigation.**
- `ConcurrencyLimitLayer` at 256 in-flight (#43), mirroring the verifier-service hardening (MED-5 in v2.x audit).
- Body limit 64 KiB (#43) — token requests are small.
- Timeout 10s per request (#43).
- JtiCache LRU-bounded at 100k entries (#42) — prevents cache-fill DoS.
- Federation-rule bounded count (#41) — prevents config-DoS amplifying per-request work.
- Token-endpoint parser fuzz harness (#51) — bug-class detection.
- Operator runbook (#53) mandates per-IP rate limiting at the edge (WAF / nginx limit_req).

**Residual risk.** Medium. ConcurrencyLimit is a fast-path defense, not a per-client rate limit. Operator must deploy edge throttling for production.

**Refs.** OWASP API Top 10 #4 (Unrestricted Resource Consumption).

---

### T08 — SPIRE Agent compromise propagation

**Description.** Compromised SPIRE Agent on the OP's node serves a forged trust bundle, causing the OP to accept attacker-signed subject_tokens as valid SVIDs.

**Attack scenario.** Attacker gains root on the OP's host and replaces the SPIRE Agent's UNIX socket or in-memory bundle. The OP fetches the forged bundle on next refresh. Attacker-signed JWT-SVIDs now verify; attacker can present any subject identifier consistent with their forged bundle and exchange for tokens bound to permitted audiences.

**Impact.** C, I, A**a** — full subject_token forgery.

**Likelihood.** Low (requires node-root) but catastrophic.

**Mitigation.**
- OP refuses to start if SPIRE Agent socket is unavailable (#45) — fail-closed.
- Bundle source pinned via `WorkloadAPI.GetX509Bundles` only — no fallback to attacker-writable paths (#45).
- Strict-mode constructor (#45) refuses silent fallback per the `Pa.Spiffe.Audit.H6` pattern (from transducer-agent).
- Node-level mitigation: operator runs OP in a hardened container with read-only filesystem; SPIRE Agent socket is the only inbound surface (#53).
- Observability: discrepancies between OP-cached bundle and SPIRE Server bundle surface in audit logs (#45).

**Residual risk.** Medium. Once node-root is achieved, every co-located service is compromised. Defense is at the layer below (host hardening), not at the OP.

**Refs.** SPIFFE Workload API spec §5.

---

### T09 — Kid lookup injection (RFC 8725 §3.10)

**Description.** Attacker submits a subject_token with `kid` header crafted to inject into a key-lookup substrate (path-traversal, SQL, LDAP, log injection).

**Attack scenario.** Attacker submits `kid = "../../etc/passwd"` or `kid = "' OR '1'='1"`. A naive lookup that interpolates the KID into a filesystem path or query crashes the OP or leaks key material.

**Impact.** Varies — at minimum availability, at worst key disclosure.

**Likelihood.** Low — only if OP uses string-interpolated lookup.

**Mitigation.**
- KID stored as RFC 7638 thumbprint (#33) — bytes-only, no interpretation.
- Constant-time KID compare in dispatch (#34) — prevents timing oracles too.
- Lookup is map-by-bytes only (#33); no path/SQL/template substrate.
- Fuzz harness (#51) tests `kid` field against arbitrary bytes.

**Residual risk.** Very Low.

**Refs.** RFC 8725 §3.10.

---

### T10 — Cross-JWT confusion (RFC 8725 §3.12)

**Description.** A JWT minted by the OP for one purpose (e.g., audience-bound access token) is accepted by an RP for another purpose (e.g., long-lived refresh).

**Attack scenario.** OP issues a short-lived access token bound to `aud = "https://rp-a.example"`. RP A's verifier doesn't distinguish access tokens from refresh tokens (both use the same audience), so attacker who captures the access token can use it where a refresh would be expected — extending access.

**Impact.** C, I.

**Likelihood.** Medium — depends on RP correctness.

**Mitigation.**
- Mandatory `typ` header on every issued token, set to `at+jwt` for access tokens per RFC 9068 (#34).
- Distinct claim sets per token kind documented in the issued-token schema (#34).
- Operator runbook (#53) requires RPs to validate `typ` header.
- KAT vectors (#49) include token-kind discrimination cases.

**Residual risk.** Low at the OP; medium on the RP side.

**Refs.** RFC 8725 §3.12, RFC 9068 §2.1.

---

### T11 — Discovery document tampering

**Description.** Adversary serves a forged `/.well-known/openid-configuration` claiming a different `jwks_uri`, `token_endpoint`, or `id_token_signing_alg_values_supported`.

**Attack scenario.** Attacker MitM's the discovery endpoint and rewrites `jwks_uri` to point at an attacker-controlled JWKS server. RP A bootstraps from the poisoned discovery doc and trusts attacker keys.

**Impact.** Equivalent to T02 (JWKS poisoning) once exploited.

**Likelihood.** Same as T02 (Low at OP, Medium upstream).

**Mitigation.**
- HTTPS-only (#43).
- ETag on discovery doc (#36).
- Discovery doc is static-after-startup — content drift triggers operator alert (#36).
- Operator runbook (#53) recommends RPs pin discovery doc thumbprint.

**Residual risk.** Same as T02.

**Refs.** OIDC Discovery 1.0 §4, RFC 8414 §3.

---

### T12 — WIMSE identifier confusion

**Description.** Attacker constructs a SPIFFE/WIMSE URI that round-trips through `CallSpiffeId` parsing but represents a different logical subject than the URI suggests (Unicode look-alikes, normalization drift, percent-encoding).

**Attack scenario.** Attacker registers a pod with SPIFFE ID `spiffe://nucleus/ns/dеfault/sa/admin` (with a Cyrillic 'е' replacing Latin 'e'). The string visually matches `spiffe://nucleus/ns/default/sa/admin` in operator dashboards but is a distinct identifier; a federation rule targeting `default` will not match, but logs and reviewers may conflate the two.

**Impact.** I, A**a** (audit confusion enabling later exploit).

**Likelihood.** Low.

**Mitigation.**
- WIMSE URI parsing enforces ASCII-only path components (#40).
- Path normalization is canonical (#40): single round-trip property test, no idempotent-after-N-rounds risk.
- Audit log emits the URI bytes verbatim AND a normalized form (#41) so reviewers see both.
- KAT vectors (#49) include Unicode-confusable test fixtures.

**Residual risk.** Very Low.

**Refs.** SPIFFE ID spec §2, Unicode UTS #39 (Security Mechanisms).

---

### T13 — Long-lived token escalation via rotation gap

**Description.** A token signed by a key that has been *rotated out* but is still in the OP's verify-set (during grace window) is accepted by an RP — even though the signing key has been marked compromised.

**Attack scenario.** Operator detects T01 (key compromise) and calls `rotate()`. The compromised key is moved out of `active_signing_key` but remains in the verify-set for the grace window (default 1h). RPs continue accepting tokens signed by the compromised key for up to 1h.

**Impact.** C, I, A**a** — extends T01's blast radius by the grace window.

**Likelihood.** Conditional on T01 occurring; given T01, High.

**Mitigation.**
- Distinct `rotate()` vs `revoke()` semantics (#37): `rotate` keeps old key in verify-set for grace; `revoke` removes it immediately.
- Operator runbook (#53) mandates `revoke()` (not `rotate()`) on suspected compromise.
- Property test (#52): revoked key is absent from /jwks.json within one polling cycle.
- Audit-log on every rotate AND revoke (#37) with reason field.

**Residual risk.** Low when operator follows runbook.

**Refs.** NIST SP 800-57 Part 1 §5.

---

## 5. STRIDE roll-up

| Threat | Spoofing | Tampering | Repudiation | InfoDisclosure | DoS | EoP |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| T01 Signing-key compromise | ✓ | ✓ | ✓ | ✓ | | ✓ |
| T02 JWKS poisoning | ✓ | ✓ | ✓ | | | ✓ |
| T03 Replay | ✓ | | ✓ | | | ✓ |
| T04 Algorithm downgrade | ✓ | ✓ | ✓ | | | ✓ |
| T05 Federation misconfig | | | | | | ✓ |
| T06 Clock skew | | | ✓ | | ✓ | |
| T07 Token endpoint DoS | | | | | ✓ | |
| T08 SPIRE compromise | ✓ | ✓ | ✓ | ✓ | | ✓ |
| T09 KID injection | | ✓ | | ✓ | ✓ | |
| T10 Cross-JWT confusion | ✓ | | | | | ✓ |
| T11 Discovery tampering | ✓ | ✓ | | | | ✓ |
| T12 WIMSE confusion | ✓ | | ✓ | | | ✓ |
| T13 Rotation gap | ✓ | | | | | ✓ |

## 6. Out of scope (v1)

- **TLS-layer attacks** (cert mis-issuance, CT-log gaps) — covered by the operator's deployment environment.
- **Side-channel attacks on Ed25519** — relies on `ed25519-dalek` upstream and its `zeroize` discipline.
- **Hardware compromise** — if attacker controls the OP's CPU, all bets are off.
- **Social engineering against operators** — addressed in the runbook, not in code.
- **Per-call SVID minting at non-boundary internal flows** — explicitly deferred to v2 per `project_per_call_spiffe_lineage` memory.

## 7. Re-review triggers

This document MUST be re-reviewed before any of:

1. Adding a new grant type to the token endpoint.
2. Adding a new key algorithm (anything beyond EdDSA).
3. Changing the federation-rule schema or matching semantics.
4. Changing the JtiCache eviction policy or replay-window TTL.
5. Adding any new endpoint that exposes OP-signed material.
6. Promoting the per-call SVID work (#46) to non-boundary internal flows.
7. Removing any algorithm-pinning CI gate (#54).

## 8. References

- RFC 6749 — OAuth 2.0 Framework
- RFC 6819 — OAuth 2.0 Threat Model
- RFC 7515 — JWS
- RFC 7517 — JWK
- RFC 7519 — JWT
- RFC 7638 — JWK Thumbprint
- RFC 8414 — OAuth 2.0 Authorization Server Metadata
- RFC 8693 — OAuth 2.0 Token Exchange
- RFC 8725 — JWT Best Current Practices
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
- OpenID Connect Discovery 1.0
- NIST SP 800-57 Part 1 — Key Management
- NIST SP 800-63C — Federation & Assertions
- SPIFFE JWT-SVID spec
- `draft-klrc-aiagent-auth-00` — Agent Identity Management System (AIMS, March 2026)
- Unit 42 — *OH-MY-DC: OIDC Misconfigurations in CI/CD*
- OWASP API Security Top 10 (2023)

## 9. Mitigation → Implementing task index

| Mitigation theme | Tasks |
|---|---|
| Encrypted KeyStore + KID thumbprint | #33 |
| JwtIssuer algorithm-pinning + zeroize | #34 |
| JWKS endpoint hardening | #35 |
| Discovery doc integrity | #36 |
| Key rotation + revocation | #37 |
| Vendor-neutrality scrub | #29, #38, #54 |
| WIMSE conformance | #30, #40 |
| Token endpoint + replay defense | #39, #42 |
| Federation rule registry | #41 |
| axum middleware (DoS, CORS, body, timeout) | #43 |
| RFC-compliant errors | #44 |
| SPIRE bundle handling | #45 |
| Boundary-only SVID minting | #46 |
| Envelope cosign | #47 |
| CLI affordances | #48 |
| Test discipline | #49, #50, #51, #52 |
| Deployment + operator runbook | #53 |
| CI gates (no-vendor + alg-pin) | #54 |
| Pre-ship audit | #55 |
| Real-RP validation | #56 |
