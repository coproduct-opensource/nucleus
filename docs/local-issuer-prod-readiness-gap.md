# LocalIssuer → JwtIssuer Production-Readiness Gap Report (P0.4 / Task #31)

**Date:** 2026-05-28
**Subject:** `crates/nucleus-lineage/src/local_issuer.rs` (+ supporting types in `issuer.rs`)
**Goal:** Enumerate every assumption that makes LocalIssuer `#[cfg(feature = "dev")]`-gated today, so #34 (Promote LocalIssuer → JwtIssuer) can close them deliberately rather than ad-hoc.
**Format:** Gap-per-issue, tagged with implementing task ID(s). No code in this document.
**Cited workspace versions:** `ed25519-dalek = "=3.0.0-pre.7"`, `jsonwebtoken = "10"`, `rand = "0.10"`.

---

## 1. Acceptance map

Task #31's acceptance criteria → gap IDs.

| Criterion | Gap IDs |
|---|---|
| (a) Key storage | GA-1 |
| (b) KID derivation/rotation | GA-2, GA-3 |
| (c) Claim schema fixing | GA-4 (cross-ref #30: GAP-3..7) |
| (d) `exp`/`nbf` validation | GA-5, GA-6 |
| (e) Replay (`jti`) handling | GA-7 |
| (f) Zeroize discipline | GA-8, GA-9 |
| (g) Signing-algorithm pinning | GA-10 |
| (h) Error-path constant-time concerns | GA-11 |
| **Additional gaps surfaced during audit** | GA-12, GA-13, GA-14, GA-15 |

15 gaps total. Each is small in isolation; collectively they justify why LocalIssuer is `dev`-gated.

---

## 2. Gap catalog

### GA-1 — Key storage is process-local, ephemeral, unrecoverable

**Severity:** **CRITICAL** for any production use.

**Where.** `local_issuer.rs:63-65` —
```rust
pub fn random() -> Result<Self, IssuerError> {
    Self::random_with("nucleus-local://demo".to_string(), Duration::from_secs(300))
}
```
Calls `SigningKey::generate(&mut csprng)` (`local_issuer.rs:70`). Fresh keypair per process. Lost on restart. Cannot be rotated meaningfully. Cannot be backed up.

**Why it matters.** Every restart breaks every outstanding token. Every replica has a different signing key. No KMS / HSM integration path. Per `THREAT_MODEL.md` T01 — signing key compromise has no recovery story today.

**Action.** Replace with `JwtKeyStore` dependency injection per task **#33**. LocalIssuer stays as a `InMemoryKeyStore`-backed convenience constructor for tests; `JwtIssuer::new(store: Arc<dyn JwtKeyStore>)` is the production interface.

**Open question.** Should `JwtIssuer` accept any `JwtKeyStore` impl, or specifically require a store that supports rotation + grace window? Recommend trait-method `JwtKeyStore::supports_rotation() -> bool` and panic-at-construction if the OP-mode caller passes a non-rotating store.

**Refs.** #33, #37.

---

### GA-2 — KID derivation is not RFC 7638-compliant

**Severity:** Medium (interop + threat-model T09 mitigation).

**Where.** `local_issuer.rs:88-91` —
```rust
let mut h = Sha256::new();
h.update(verifying_key.as_bytes());
let kid_bytes = h.finalize();
let key_id = URL_SAFE_NO_PAD.encode(&kid_bytes[..12]);
```

The KID is the first 12 bytes of SHA-256(public_key_raw_bytes), base64url-encoded — a 16-char identifier. This is **stable** (good) but **not** the RFC 7638 JWK thumbprint, which hashes the canonical JWK JSON representation: `SHA-256({"crv":"Ed25519","kty":"OKP","x":"<base64url>"})`.

**Why it matters.**
1. Interop: RPs that compute the expected KID from a fetched JWK (RFC 7638-compliant tooling does this) will get a different value than ours.
2. Threat model T09 (KID injection): The constant-time discipline only works if KIDs are bytes-compared. Truncating to 12 bytes shrinks the namespace; collisions are still astronomically rare but the surface is real.
3. Per `THREAT_MODEL.md` mitigation list: "KID = RFC 7638 thumbprint (#33) so a stolen key cannot be re-published under a different KID without detection." Today this property does not hold.

**Action.** In #33 (`JwtKeyStore` design): compute KID via RFC 7638 over the canonical JWK form. Document the deviation as a migration step — old (12-byte SHA-256) and new (RFC 7638) KIDs coexist for one grace window during rollout.

**Open question.** Truncate the RFC 7638 thumbprint or use the full 32-byte value as base64url (43 chars)? Recommend full value — KID length is unconstrained and full thumbprint is what tooling expects.

**Refs.** #33, #34, threat model T09.

---

### GA-3 — No rotation primitive at all

**Severity:** **CRITICAL** for any production deployment.

**Where.** Entire `LocalIssuer` struct (`local_issuer.rs:52-59`). Stores one `SigningKey` for the lifetime of the instance. No `rotate()`, no `revoke()`, no grace window, no `JwtKeyStore` indirection.

**Why it matters.** Per `THREAT_MODEL.md` T01 and T13: without rotation, key compromise is unrecoverable except by total service restart with a new identity — which breaks every outstanding token. NIST SP 800-57 Part 1 §5 requires planned rotation; there is no path today.

**Action.** This is exactly task **#37**. LocalIssuer-the-test-double doesn't need rotation; `JwtIssuer`-the-production-OP MUST have it. Implementation lives in `JwtKeyStore` (#33) + `KeyRotator` (#37).

**Refs.** #33, #34, #37, threat model T01 + T13.

---

### GA-4 — Claim schema gaps (`typ`, `client_id`, `scope`, `act`, `nucleus_kind` naming)

**Severity:** Medium for each individual claim, aggregating to High.

**Where.** `local_issuer.rs:172-184`, `issuer.rs::SvidClaims` (lines 38-50).

**Why it matters.** Catalogued in detail in #30 (`docs/wimse-aims-conformance-gap.md` §2 GAP-3..7). Re-listed here for self-containment:

- **GAP-3 (RFC 9068 §2.1):** `typ` JWT header not set; jsonwebtoken defaults to `"JWT"`. Must be `"at+jwt"` for OAuth 2.0 access tokens. This is a real MUST violation today.
- **GAP-4 (RFC 9068 §2.2):** `client_id` claim missing. Required.
- **GAP-5 (RFC 9068 §2.2):** `scope` claim missing.
- **GAP-6 (RFC 8693 §4.1):** `act` (delegated actor) claim missing — needed when token-exchange has actor_token.
- **GAP-7 (RFC 7519 §4.3):** `nucleus_kind` is a bare-named private claim; should be `urn:nucleus:kind`.

**Action.** Closed by the PR-A through PR-G plan in `docs/wimse-aims-conformance-gap.md`. Implementer of #34 lifts the field set from there.

**Refs.** #30 (gap analysis), #34, #40 (WIMSE conformance), #49 (KAT vectors).

---

### GA-5 — No `nbf` (not-before) claim

**Severity:** Low (RFC 7519 optional). Documented here so #34's implementer can make a deliberate choice.

**Where.** `local_issuer.rs:176-184` — `SvidClaims` is constructed with `iat`, `exp`, but no `nbf`.

**Why it matters.** RFC 7519 §4.1.5 makes `nbf` optional. AIMS doesn't reference it. RFC 9068 doesn't require it. Adding `nbf` introduces clock-skew surface (threat model T06) without observable benefit at our token lifetimes (≤1h).

**Action.** **Do NOT add `nbf`** in v1. Document the decision in `JwtIssuer`'s rustdoc with the rationale: "we ship at-issuance tokens whose `iat` doubles as `nbf` minus 0s; explicit `nbf` would force RPs to handle clock-skew leeway twice." Re-evaluate if a real RP demands it.

**Refs.** #34, threat model T06.

---

### GA-6 — Default lifetime 5 minutes vs `THREAT_MODEL.md` 1h cap

**Severity:** Low (the longer cap is the harder problem; the shorter default is conservative).

**Where.** `local_issuer.rs:64` — default `Duration::from_secs(300)`.

**Why it matters.** Threat model T03 (replay across audiences) calls for a hard cap of 1h; our LocalIssuer default is 5 min, which is *tighter*. That's good for security but possibly inconvenient for federated RPs that don't poll JWKS often. The hard cap belongs in `JwtIssuer`, not the constructor.

**Action.** In `JwtIssuer` (#34): constructor accepts `lifetime: Duration`, asserts `lifetime <= JWT_ISSUER_MAX_LIFETIME = 3600s` at construction. Default 5min preserved for backward compatibility; production deployments can opt up to 1h.

**Refs.** #34, threat model T03.

---

### GA-7 — No `jti` replay defense on the issuer side

**Severity:** Low (replay is the verifier's responsibility per RFC 7519 §4.1.7).

**Where.** `local_issuer.rs:181` — `jti: Uuid::new_v4().to_string()`. Per-call random UUID. The issuer never re-checks whether it has already issued this jti (impossible to collide via uuidv4, so a moot concern), and the issuer does NOT track issued jtis for later replay defense.

**Why it matters.** Replay defense (JtiCache) lives at the OP's *token endpoint* (inbound side) per #42 and at the *RP's* side per their own implementation. The issuer doesn't track jtis it minted; if it did, it would be a massive memory footprint with no value (only the *receiver* sees a replay). This is correct as designed.

**Action.** No change to LocalIssuer. JtiCache integration (#42) is at the OP's token endpoint, not the issuer.

**Refs.** #34, #42, threat model T03.

---

### GA-8 — SigningKey zeroize: relies on default features

**Severity:** Medium (a transitive feature-flag flip could disable it silently).

**Where.** Cargo.toml: `ed25519-dalek = "=3.0.0-pre.7"`. No explicit `zeroize` feature requested.

**Why it matters.** Per crates.io / docs.rs: "All signing keys are zeroed when they go out of scope (unless zeroize is disabled)." This relies on ed25519-dalek's default features including `zeroize`. If a workspace-wide `default-features = false` rolls in (e.g., for a no_std build) — silent regression.

**Action.** In `crates/nucleus-oidc-provider/Cargo.toml` (#32): pin **explicitly**:
```toml
ed25519-dalek = { version = "=3.0.0-pre.7", features = ["zeroize"] }
```
Add a CI test that asserts `SigningKey` implements `ZeroizeOnDrop` (compile-time check via trait bound).

**Refs.** #32, #34.

---

### GA-9 — PKCS8 DER intermediate is sensitive but not explicitly zeroized

**Severity:** Medium.

**Where.** `local_issuer.rs:82-85` —
```rust
let pkcs8 = signing_key
    .to_pkcs8_der()
    .map_err(|e| IssuerError::KeyEncoding(e.to_string()))?;
let encoding_key = EncodingKey::from_ed_der(pkcs8.as_bytes());
```

The PKCS8 DER bytes contain the private key material. `pkcs8::Document` returns either a `SecretDocument` (which zeroizes) or a `Document` (which may not). On the jsonwebtoken side, `EncodingKey::from_ed_der` copies the bytes into its internal representation — that copy persists for the lifetime of the issuer. When `EncodingKey` is dropped, **jsonwebtoken 10 does not zeroize**.

**Why it matters.** Adversary with memory-read (post-compromise forensics, core dump access, swap-file recovery) recovers the signing key from `EncodingKey`'s internal storage.

**Action.** Two-part fix in `JwtIssuer` (#34):
1. Use `SecretDocument::to_pkcs8_der()` form so the intermediate zeroizes (verify ed25519-dalek 3.0-pre.7 returns SecretDocument when `pkcs8` feature is enabled).
2. Wrap `EncodingKey` in a custom type that zeroizes on drop. Or — better — drop the conversion entirely: jsonwebtoken 10 can sign with raw `SigningKey` directly via the `rust_crypto` feature path, no PKCS8 round-trip. Confirm and switch.

**Open question.** Does jsonwebtoken 10's `rust_crypto`-feature signing path call ed25519-dalek directly and thus inherit its zeroize? Audit needed during #34.

**Refs.** #34, threat model T01.

---

### GA-10 — Signing-algorithm pinning is correct on encode; verify side is somebody else's problem

**Severity:** Low (issuer side correctly pinned).

**Where.** `local_issuer.rs:185` — `Header::new(Algorithm::EdDSA)`.

**Why it matters.** Encode-side alg pinning prevents the issuer from emitting non-EdDSA tokens. ✓ Correct. The *decode* side (RP's verification of our tokens) is the RP's responsibility — we publish JWKS with `alg: EdDSA`, and any RP that respects RFC 8725 §3.1 will alg-pin from the JWK. RPs that don't are vulnerable; we cannot fix that.

The CVE landscape in 2026 (CVE-2026-22817, CVE-2026-27804, CVE-2026-23552) is overwhelmingly about RP-side validators that fail to alg-pin. Our issuer is not in that class.

**Action.** No issuer-side change. **In `JwtIssuer` (#34) construction**: assert at compile time that `Algorithm` is `EdDSA` only; explicit-reject `HS*`, `RS*`, `ES*`, `none`. CI gate (#54) enforces this via static-source check.

Add a defensive runtime assertion: `assert_eq!(header.alg, Algorithm::EdDSA)` after `Header::new(...)` in case a future jsonwebtoken update changes default behavior.

**Refs.** #34, #54, threat model T04.

---

### GA-11 — KID compare and error path: timing observability

**Severity:** Low (single-key issuer has no KID lookup; multi-key store does).

**Where.** Conceptual — `LocalIssuer` has a single `key_id` and never does KID lookup. Future `JwtIssuer`-with-`JwtKeyStore` (#33) will lookup-by-KID, and that lookup MUST be constant-time per threat model T09.

**Why it matters.** If a verify path does `self.keys.get(kid)` on a `HashMap`, the lookup is O(1) average and the timing leaks whether the KID was in the map. For a small map (few keys during grace window), the difference is microseconds; a remote attacker measuring round-trip latency could infer key-set membership. The threat is small (knowing a KID exists doesn't grant access) but the mitigation is cheap.

**Action.** `JwtKeyStore::verify_key(kid)` (#33) returns `Result<Arc<DecodingKey>, ...>` and the *error path* takes the same code path as the success path (no early return based on lookup miss). Verify with a property test that measures cycles for known-good vs known-bad KIDs.

**Open question.** Is this overkill for an OP-internal lookup, given an adversary cannot directly time the lookup (they observe HTTP latency dominated by network)? Recommend implementing anyway — it's cheap and closes the defense-in-depth gap. Document the rationale.

**Refs.** #33, threat model T09.

---

### GA-12 — `warn_once` is the entire "don't use in production" gate

**Severity:** Critical at promotion time (silent gate failure).

**Where.** `local_issuer.rs:28-42` — `static WARNED: AtomicBool` + `tracing::warn!` on first use.

**Why it matters.** Today: `#[cfg(feature = "dev")]` on the crate boundary plus `warn_once` is the *only* mechanism preventing accidental production use. When #34 lands `JwtIssuer` as the production type, the warning text becomes wrong and misleading.

**Action.** In #34: delete `warn_once` and `WARNED`. Replace with `JwtIssuer::new()` constructor invariants (asserted at construction): issuer URL is HTTPS, KeyStore is rotation-capable, lifetime ≤ 1h. `LocalIssuer` then becomes a thin wrapper: `LocalIssuer::random() -> JwtIssuer { JwtIssuer::new(InMemoryKeyStore::ephemeral(), "nucleus-local://demo", 300s).unwrap() }`.

**Open question.** Should `LocalIssuer` continue to exist as an alias after #34, or be deleted? Recommend keep behind `dev` feature for one release as the deprecated alias; delete in the next release. Avoids churn in dependent tests.

**Refs.** #34.

---

### GA-13 — `signing_key()` accessor leaks the private key

**Severity:** Medium (test-only accessor in production-bound code).

**Where.** `local_issuer.rs:125-127` —
```rust
pub fn signing_key(&self) -> &SigningKey {
    &self.signing_key
}
```

**Why it matters.** The accessor exists so tests can construct an `issuer_b` that shares an identity with `issuer_a` (verified by the round-trip tests). It returns `&SigningKey` — leaking a borrowed handle to the private key into any caller. For a production `JwtIssuer` this is wrong: callers should never see the raw key.

**Action.** In `JwtIssuer` (#34): **delete this accessor**. Provide instead a `share_keystore(&self) -> Arc<dyn JwtKeyStore>` that returns the same KeyStore handle by reference-counting. Tests that need to "construct another issuer with the same identity" use the shared KeyStore.

**Refs.** #33, #34.

---

### GA-14 — `from_signing_key` takes raw `SigningKey` by value

**Severity:** Low for tests, deprecated for production.

**Where.** `local_issuer.rs:76-80`.

**Why it matters.** Constructing from a raw key bypasses any KeyStore discipline (rotation, encryption-at-rest, audit). For tests it's necessary; for production it's a backdoor.

**Action.** In `JwtIssuer` (#34): gate this constructor behind `#[cfg(any(test, feature = "dev"))]` so production builds cannot call it. Force production callers through `JwtIssuer::new(keystore, ...)`.

**Refs.** #33, #34.

---

### GA-15 — No `at_hash` / `c_hash` claims (OIDC ID-Token semantics)

**Severity:** Informational. Not relevant for OAuth 2.0 access tokens; relevant if we ever issue ID tokens.

**Where.** `SvidClaims` has no `at_hash` / `c_hash`.

**Why it matters.** OIDC Core §3.1.3.6 requires `at_hash` in ID tokens when issued alongside an access token. We are not issuing ID tokens in v1 (we mint JWT-SVIDs and OAuth 2.0 access tokens), so this is N/A. If we ever add an OIDC OP role (full user-authentication, not just workload identity), this becomes required.

**Action.** Document as out-of-scope for v1 in `crates/nucleus-oidc-provider/THREAT_MODEL.md` §6.

**Refs.** Future v2 if/when ID tokens land.

---

## 3. Severity roll-up

| Severity | Count | Gaps |
|---|---|---|
| **Critical** | 3 | GA-1, GA-3, GA-12 |
| **Medium** | 7 | GA-2, GA-4 (×5 sub-gaps from #30), GA-8, GA-9, GA-13 |
| **Low** | 4 | GA-5, GA-6, GA-7, GA-10, GA-11, GA-14 |
| **Informational** | 1 | GA-15 |

**The three Criticals are why LocalIssuer is `dev`-gated.** Closing them is the entirety of why #33 (JwtKeyStore), #34 (JwtIssuer), and #37 (rotation) exist.

---

## 4. Verification gates before #34 ships

A skeptical reviewer (per `nucleus/CLAUDE.md` discipline) MUST see all of:

1. **Static check:** `grep -E '(HS[0-9]+|RS[0-9]+|"none"|alg.*none)' crates/nucleus-oidc-provider/src/` returns no non-test matches. (Covered by #54.)
2. **Compile-time check:** `SigningKey: ZeroizeOnDrop` trait bound asserted in a unit test.
3. **Wire-format check:** Sample JWT decoded from `JwtIssuer` shows `typ: "at+jwt"`, `alg: "EdDSA"`, RFC 7638 KID, all required RFC 9068 claims present.
4. **Rotation property test:** A token signed pre-rotation verifies during grace, fails after. (Covered by #52.)
5. **Threat-model alignment:** Each `THREAT_MODEL.md` Critical / High mitigation has a passing test.
6. **No `warn_once`-style runtime gate** in `JwtIssuer` constructor — all invariants asserted, not warned.

---

## 5. Open questions for the implementer of #34

1. **Backward-compat with LocalIssuer-using tests:** keep `LocalIssuer` alias for one release (recommended) vs delete now (atomic but churns more tests)?
2. **`pkcs8` round-trip:** is the PKCS8 intermediate avoidable via direct ed25519-dalek signing in jsonwebtoken 10's `rust_crypto` path? Profile + audit during #34.
3. **`JwtKeyStore::verify_key` constant-time discipline:** worth the cost (small map, microsecond difference) or document as known acceptable risk?
4. **Lifetime cap:** keep 1h hard cap or allow `--no-cap` for explicit operator opt-in (e.g., long-lived service-to-service tokens in air-gapped envs)? Recommend hard cap, no escape hatch.
5. **`signing_key()` accessor removal:** does any non-test code depend on it? Grep workspace first; if zero hits, delete; if non-zero, document migration before deleting.

---

## 6. References

- `crates/nucleus-lineage/src/local_issuer.rs` (current implementation)
- `crates/nucleus-lineage/src/issuer.rs` (trait + claims + error)
- `docs/wimse-aims-conformance-gap.md` (#30 — sibling audit; GAP-3..7 expand GA-4)
- `crates/nucleus-oidc-provider/THREAT_MODEL.md` (#28 — T01, T03, T04, T06, T09, T13 inform several gaps)
- `docs/oidc-vendor-neutrality-audit.md` (#29 — sibling structural audit)
- RFC 7517 (JWK), RFC 7638 (JWK Thumbprint)
- RFC 7519 (JWT), RFC 8725 (JWT BCP), RFC 9068 (JWT-as-Access-Token)
- NIST SP 800-57 Part 1 §5 (key rotation)
- ed25519-dalek 3.0-pre.7 docs (zeroize defaults)
- jsonwebtoken crate 2026 CVE landscape (CVE-2026-22817, -27804, -23552 — RP-side alg-confusion)
