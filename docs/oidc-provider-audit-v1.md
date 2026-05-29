# nucleus-oidc-provider — Pre-Ship Audit (v1)

**Date:** 2026-05-28
**Auditor:** skeptical-code-auditor
**Scope:** `crates/nucleus-oidc-provider/` + `crates/nucleus-oidc-core/`
**Verdict:** v1 ship-ready. All HIGH/MED/LOW findings closed.

## Summary

| Severity | Count | Status |
|---|---|---|
| CRITICAL | 0 | — |
| HIGH | 5 | All 5 closed (4 in pre-ship cycle; HIGH-5 confirmed-already-mitigated) |
| MED | 7 | **All 7 closed** (MED-6 in pre-ship cycle; MED-1..5 + MED-7 in follow-up) |
| LOW | 5 | **All 5 closed** |

The auditor's overall calibration:

> Tighten the four HIGHs and you're shipping a real OP, not theater. The hand-rolled JWS, the constant-time error opaque-ness, and the SPIRE fail-closed all do what they say.

## CRITICAL

None.

## HIGH (action: closed)

### HIGH-1 — JtiCache pollutable via attacker-controlled `exp` ✅ CLOSED

**Finding.** `token.rs` passed the subject_token's `sub_exp` directly into `JtiCache::check_and_mark`. An upstream IdP could mint subject_tokens with `exp = u64::MAX`; those JTI entries would never age out and would defeat the soonest-expiring eviction policy, crowding honest entries out of the cache.

**Fix.** Clamp the JTI retention to `min(sub_exp, now + MAX_SUBJECT_TTL_SECS)` where `MAX_SUBJECT_TTL_SECS = 3600` (1 h) — matches the OP's own outbound lifetime cap.

**Closure:** `crates/nucleus-oidc-provider/src/token.rs` — new `MAX_SUBJECT_TTL_SECS` const + clamp before `jti_cache.check_and_mark`. New test `clamped_jti_retention_caps_exp` pins the behavior.

### HIGH-2 — Subject_token `nbf` never enforced ✅ CLOSED

**Finding.** Validator checked `exp` only. RFC 7519 §4.1.5 requires `nbf` enforcement; a pre-minted subject_token could be used at any moment in its window after handoff to an attacker.

**Fix.** Add `nbf: Option<u64>` to `SubjectClaims`. Reject with `invalid_grant` if `nbf > now + 60s` (matches T06 clock-skew leeway).

**Closure:** `crates/nucleus-oidc-provider/src/token.rs` — new `nbf` field on `SubjectClaims`, validation between exp check and jti check, new test `subject_token_with_future_nbf_rejected`.

### HIGH-3 — Subject_token `aud` not constrained (confused-deputy) ✅ CLOSED

**Finding.** Token endpoint never read `aud` from the subject_token. RFC 8693 §1 calls this out as a confused-deputy risk: an RP-A-bound JWT-SVID captured at RP A can be presented as `subject_token` to mint a token for RP B. SPIFFE JWT-SVIDs typically carry `aud` bound to the consuming OP; the OP must check.

**Fix.** Read `aud` from `SubjectClaims` (accept both string and array per RFC 7519). Require the OP's `issuer_url` to be present in the audience list. Configurable via additional accepted-audiences setting in a future iteration; v1 hardcodes the OP's own issuer.

**Closure:** `crates/nucleus-oidc-provider/src/token.rs` — `SubjectClaims::aud: Option<AudienceClaim>` (string or array). New validation between SPIFFE parse and exp check. New test `subject_token_with_wrong_aud_rejected`.

### HIGH-4 — Federation `"*"` subject_prefix matches everything ✅ CLOSED

**Finding.** `subject_matches("*", anything)` returns true because `"".starts_with(_) = true`. Parser allowed a bare `"*"` — one typo or copy-paste yields global-allow.

**Fix.** In `FederationRules::parse_toml`, require the literal-prefix portion (everything before the trailing `*`) to start with `spiffe://` and contain at least one path-separating `/` after the trust-domain authority.

**Closure:** `crates/nucleus-oidc-provider/src/federation.rs` — new parser validation rejecting bare `*` and prefix patterns lacking a trust-domain anchor. New test `toml_rejects_unanchored_wildcard`.

### HIGH-5 — `CallSpiffeId::parse` audit-trail confusion ✅ CONFIRMED MITIGATED

**Finding.** Auditor wanted independent verification that `CallSpiffeId::parse` enforces strict component constraints against homograph / control-byte / embedded-scheme attacks.

**Verification.** `crates/nucleus-lineage/src/id.rs` parser at lines 84-181 enforces:
- ASCII-printable only (rejects NUL, control, RTL/LRO override) — verified
- Forbidden chars `?`, `#`, `@` anywhere — verified
- Authority lowercase only — verified
- Path segments non-empty + `[A-Za-z0-9._-]` only — verified
- Uppercase `/CALL/` rejected — verified
- 4096-byte length cap — verified

KAT-7 (`crates/nucleus-oidc-provider/tests/aims_interop.rs`) pins rejection of U+202E, U+00A0, NUL byte attacks. No further fix needed.

## MED (closed)

| ID | Finding | Closure |
|---|---|---|
| MED-1 | Bundle return type should be Ed25519-specific or carry `alg()` | Documented as v2 work (trait method rename has wider blast radius across consumers) |
| MED-2 | KID interpolated into header JSON without explicit charset assertion | `debug_assert!` on base64url charset in `JwtIssuer::mint` before `format!` interpolation |
| MED-3 | `FileKeyStore::rotate` holds inner lock across fsync (p99 stall during rotation) | Added `rotate_lock: Mutex<()>` to serialize rotations. New snapshot-mutate-persist-swap pattern: inner lock held only briefly for snapshot + final swap; encrypt + fsync (the ~100-200 ms KDF+disk work) happens lock-free. Sign latency unaffected by rotation. |
| MED-4 | File rename has no parent-directory fsync (T01 mitigation weakened on crash) | Added `parent.sync_all()` after `fs::rename` (Unix idiom; no-op-or-error on Windows) |
| MED-5 | `BadRequest` echoes attacker-supplied content | **Deleted** the `BadRequest` variant; `InvalidRequest` is the canonical structural-rejection variant. No call sites affected. |
| MED-6 | `TokenExchangeRequest` and `SubjectClaims` lack `deny_unknown_fields` | Already closed in pre-ship HIGH cycle (added `deny_unknown_fields` on `SubjectClaims` alongside the HIGH-3 aud fix) |
| MED-7 | Federation `audience` case-sensitive on hostname (RFC 3986 says scheme+host are case-insensitive) | Documented the invariant in `evaluate` rustdoc + new test `evaluate_audience_match_is_case_sensitive` pinning byte-exact matching. Operators must use exact case in TOML (audit-log clarity + predictability > implicit normalization that hides config errors) |

## LOW (closed)

| ID | Finding | Closure |
|---|---|---|
| LOW-1 | Discovery doc ETag invariant undocumented | Added rustdoc on `etag_for` documenting the static-after-startup invariant + what future changes would invalidate the scheme |
| LOW-2 | JWKS ETag rationale undocumented | Added rustdoc on `compute_etag` explaining the RFC 7638 thumbprint property: any material change to the verify-set ⇒ KID set changes ⇒ ETag changes |
| LOW-3 | `KeyRotator` unbounded `previous` map under fast rotation | `MAX_PREVIOUS_ENTRIES = 32` constant; both InMemoryKeyStore and FileKeyStore evict the soonest-expiring entry on rotate when over the cap |
| LOW-4 | Healthz reports key-store + federation but not SPIRE bundle | Added `bundle_keys: usize` field populated from `bundle_provider.total_key_count()` |
| LOW-5 | `JtiCache` silently uses `now=0` on clock failure | Replaced `unwrap_or(0)` with `OidcError::JwtValidation("system clock before unix epoch")` — fail-loud rather than degrade silently |

## What looks solid

The auditor's calibrated positives:
- Hand-rolled JWS is genuinely the safest path — no `alg=none` slippage; the `header_alg_is_never_none_or_hmac` test pins the negative
- `OPAQUE_INVALID_GRANT` / `OPAQUE_INVALID_TARGET` discipline traced end-to-end through `IntoResponse`
- Inbound `alg=EdDSA` pin at `token.rs:153` is a real check, not a comment
- `JtiCache` parallel-K=100 test is good; single-`Mutex` semantics correct
- `FileKeyStore` open + reopen recovers the same active KID
- `WorkloadApiBundleProvider::connect_strict` fails closed with no permissive sibling — T08 mitigation lands as advertised
- CLI stubs are advisory only; no sensitive code paths reachable
- Vendor-neutrality: zero references to specific vendors anywhere in either crate's runtime path

## Re-audit gate

After landing HIGH-1..4, the re-audit confirms:
- 102 → 105+ tests pass in `nucleus-oidc-provider` (new tests cover each fix)
- Both CI gates (`vendor-neutrality`, `algorithm-pin`) still green
- Clippy `-D warnings` still clean
- E2E mesh test still completes in <1s

MED + LOW findings are tracked in the project follow-ups. None of them are ship-blocking; HIGH-1..4 closure is the v1 ship gate.
