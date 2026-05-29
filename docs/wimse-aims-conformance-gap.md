# WIMSE / AIMS Conformance Gap Analysis (P0.3 / Task #30)

**Date:** 2026-05-28
**Subject:** `crates/nucleus-lineage/src/id.rs` (`CallSpiffeId`) + `crates/nucleus-lineage/src/local_issuer.rs` (JWT claims)
**Goal:** Catalog where the current implementation deviates from `draft-klrc-aiagent-auth-01` (AIMS) and `draft-ietf-wimse-identifier-00` (WIMSE Workload Identifier), and produce PR-sized actions for #40 (WIMSE conformance on `CallSpiffeId`) and #34 (`JwtIssuer` claims).
**Cited drafts** (verified May 2026):
- `draft-klrc-aiagent-auth-00` (2026-03-02, Informational; -01 in progress)
- `draft-ietf-wimse-identifier` (2026-03-02, Standards Track)
- `draft-ietf-wimse-arch-07` — WIMSE Architecture
- `draft-ietf-wimse-wpt-01` — Workload Proof Token (out of v1 scope, documented as future work)

---

## 1. Verdict at a glance

| Aspect | Current state | AIMS / WIMSE position | Verdict |
|---|---|---|---|
| Identifier URI scheme | `spiffe://…` | AIMS: "WIMSE identifier MAY be a SPIFFE ID"; WIMSE Workload Identifier uses `wimse://` but no conversion mechanism specified | **Conformant.** We map SPIFFE IDs onto WIMSE identifiers per AIMS §3. Optional `wimse://` alias for future. |
| Trust domain (authority) | Lowercase ASCII `[a-z0-9._-]`, no port, no userinfo | WIMSE: SHOULD be FQDN; MUST be non-empty; no port/userinfo/query/fragment | **Conformant** on hard MUSTs. SHOULD-FQDN enforcement is missing (currently advisory). |
| Path component | SPIFFE charset `[A-Za-z0-9._-]` + reserved `sha256:<hex>` last-segment form | WIMSE: deployment-specific, no spec-level restriction | **Conformant.** We are *stricter* than WIMSE requires. |
| URI max length | 4096 bytes (`MAX_URI_LEN`) | WIMSE: SHOULD NOT exceed 2048 bytes | **SHOULD violation.** Documented rationale required (per-call SVID paths with content-hash suffixes need headroom). |
| Query / fragment / userinfo | Hard-rejected at parse (`?`, `#`, `@`) | WIMSE: MUST NOT be present | **Conformant.** Defense-in-depth: we reject anywhere, not only at canonical positions. |
| ASCII-only path | Enforced; non-ASCII rejected at parse | WIMSE: no explicit restriction | **Conformant.** Stricter than spec; rejects RTL/LRO homograph attacks (per threat model T12). |
| JWT `iss` claim | Set (default `nucleus-local://demo` for `LocalIssuer`) | RFC 9068: required; OIDC: SHOULD be HTTPS URL resolving to discovery doc | **Conformant for LocalIssuer (dev only). Gap for JwtIssuer (#34)** — production issuer URL MUST be the OP's HTTPS issuer URL. |
| JWT `sub` claim | Set (the agent's `CallSpiffeId`) | AIMS: sub conveys "the User or System identifier" when delegating; RFC 9068: required | **Conformant.** |
| JWT `aud` claim | Set (single-valued string) | RFC 9068: required; AIMS: references scope/aud as "relevant to authorization" | **Conformant.** |
| JWT `iat`, `exp` | Set (default 300s lifetime) | RFC 9068: required; AIMS implicit via reference | **Conformant.** |
| JWT `jti` | Set (UUIDv4) | RFC 9068: SHOULD; RFC 8725 §3.6: recommended for replay defense | **Conformant.** |
| JWT `typ` header | NOT explicitly set (relies on `jsonwebtoken`'s default `JWT`) | RFC 9068: MUST be `at+jwt` for access tokens | **VIOLATION.** See GAP-3. |
| JWT `client_id` | NOT present | RFC 9068: required for access tokens | **VIOLATION.** See GAP-4. |
| JWT `scope` | NOT present | RFC 9068: required when scoped; AIMS implicit | **GAP.** See GAP-5. |
| JWT `act` (actor) | NOT present | RFC 8693 §4.1: required for delegated tokens; AIMS: delegation via sub/act | **GAP.** See GAP-6. |
| JWT `cnf` (confirmation) | NOT present | WIMSE WPT: required for proof-of-possession bound tokens | **DEFERRED** — bearer-only in v1. |
| Custom claim `nucleus_kind` | Bare-named string | RFC 7519 §4.3: private claims SHOULD use collision-resistant namespace (URN or URL) | **MINOR.** See GAP-7. |
| Federation flow | Planned for #39 via RFC 8693 token exchange | AIMS: prescribes RFC 8693 as the mechanism | **Conformant by plan.** |

---

## 2. Gap catalog

### GAP-1 — URI max length 4096 > WIMSE SHOULD-NOT-exceed 2048

**Severity:** Low (SHOULD violation, documented rationale acceptable).

**Where.** `crates/nucleus-lineage/src/id.rs:52` — `pub const MAX_URI_LEN: usize = 4096`.

**Why we exceed.** Per-call SVIDs append `/call/<uuid>/<kind>/<content-hash>` segments to the pod root. Worst case: pod root (~80 chars) + 5 nested call segments × (uuid 36 + tag 16 + `sha256:<64>` 71) = ~700 chars. We have headroom but the published 2048 limit is enough.

**Action.** Lower `MAX_URI_LEN` to 2048 OR document the deviation. **Recommend keeping 4096** for headroom and document the choice. AIMS does not echo this WIMSE SHOULD, and worst-case real lineage depth is bounded; 4096 is safe vs HTTP header limits (8K typical) and SPIRE Agent socket buffer limits (64K).

**PR.** ~10 LoC. Add a doc-comment to `MAX_URI_LEN` citing `draft-ietf-wimse-identifier §3.2` and the rationale.

---

### GAP-2 — No FQDN enforcement on trust-domain authority

**Severity:** Low (SHOULD).

**Where.** `crates/nucleus-lineage/src/id.rs:130-137` — authority charset check accepts `[a-z0-9._-]` without requiring at least one dot.

**Why.** WIMSE §3.1: "Fully qualified domain names SHOULD be used … IP addresses MUST NOT be used except for legacy compatibility." Our parser accepts `spiffe://nucleus/...` (single-label) which is technically not an FQDN.

**Action.** **DO NOT** enforce at parse time — backwards-compat break. Instead, add an admission-time validator in `crates/nucleus-spec` that rejects non-FQDN trust domains in `PodSpec`. Issue an additional `tracing::warn!` from `LocalIssuer` constructor when issuer URL authority isn't FQDN-shaped.

**PR.** ~30 LoC in `nucleus-spec` PodSpec validator + test cases for FQDN + non-FQDN. Don't touch `id.rs`.

---

### GAP-3 — Missing JWT `typ` header `at+jwt` per RFC 9068

**Severity:** Medium (interop + cross-JWT confusion).

**Where.** `crates/nucleus-lineage/src/local_issuer.rs:185-186` —
```rust
let mut header = Header::new(Algorithm::EdDSA);
header.kid = Some(self.key_id.clone());
```
The `typ` header is not set; `jsonwebtoken` defaults to `JWT`.

**Why it matters.** RFC 9068 §2.1 mandates `typ: "at+jwt"` for OAuth 2.0 access tokens. This is also the mitigation for threat model T10 (cross-JWT confusion). RPs that distinguish access-tokens from id-tokens/refresh-tokens (LlamaGuard-style RPs do not, but most do) reject tokens with wrong `typ`.

**Action.** Set explicitly in `JwtIssuer` (#34). Pin via constructor:
```rust
let mut header = Header::new(Algorithm::EdDSA);
header.typ = Some("at+jwt".to_string());
header.kid = Some(self.key_id.clone());
```
For `LocalIssuer` (dev): match the same behavior so dev round-trips match production.

**PR.** ~5 LoC + KAT vector in #49 confirming `typ` is present and equals `at+jwt`.

---

### GAP-4 — Missing `client_id` claim

**Severity:** Medium.

**Where.** `crates/nucleus-lineage/src/issuer.rs::SvidClaims` (per the imports in `local_issuer.rs:24` — the struct is defined there).

**Why it matters.** RFC 9068 §2.2 lists `client_id` as required for access tokens. AIMS leaves the semantic open. For nucleus's case:
- For pod-bound tokens minted in-process: `client_id = sub` (the pod IS its own client).
- For token-exchange outputs (#39): `client_id = federation rule identifier` (the rule that authorized the exchange).

**Action.** Add `client_id: String` to `SvidClaims`. Populate in `fetch_jwt_svid_with_kind` with the subject's own SPIFFE ID; override at the token-exchange call site.

**PR.** ~25 LoC. New field on `SvidClaims`; new field on `IdentityFetcher::fetch_jwt_svid_with_kind` (or a builder). Backward-compat: existing tests still pass because we set a sensible default.

---

### GAP-5 — Missing `scope` claim

**Severity:** Medium.

**Where.** `SvidClaims` — no `scope` field.

**Why it matters.** RFC 9068 §2.2 requires `scope` when scoped. AIMS pivots authorization on it. Without it, federation rules cannot encode "this exchange authorizes only read-only access to RP A's /metrics endpoint."

**Action.** Add `scope: Option<String>` to `SvidClaims`. Default `None` for pod-bound tokens; populate from federation rule's `allowed_grants` for token-exchange outputs (#41).

**PR.** ~30 LoC including KAT vector + integration test that scope round-trips through the token-exchange path.

---

### GAP-6 — Missing `act` (actor) claim for delegation

**Severity:** Medium (required when delegation occurs; not required for non-delegated tokens).

**Where.** `SvidClaims`.

**Why it matters.** RFC 8693 §4.1 prescribes `act` for any token issued via token-exchange where there is an actor token. The structure is recursive: `act` may itself contain `act` for multi-hop delegation.

```jsonc
{
  "sub": "spiffe://nucleus/ns/agents/sa/coder",  // ultimate principal
  "act": {
    "sub": "spiffe://nucleus/ns/agents/sa/coder/call/<uuid>",  // immediate actor
    "act": { "sub": "..." }  // further hops
  }
}
```

**Action.** Add `act: Option<Box<DelegatedActor>>` where `DelegatedActor` has `sub: String, act: Option<Box<DelegatedActor>>`. Populated only when token-exchange has `actor_token` (#39).

**PR.** ~45 LoC including the recursive type, serde round-trip, and a KAT for two-hop delegation.

---

### GAP-7 — `nucleus_kind` is a bare-named private claim

**Severity:** Low.

**Where.** `crates/nucleus-lineage/src/local_issuer.rs:183` — `nucleus_kind: kind.map(|s| s.to_string())`.

**Why it matters.** RFC 7519 §4.3 says private claims SHOULD use a collision-resistant name — a URI or URN. Bare `nucleus_kind` could collide with another extension that picked the same name.

**Action.** Two equally-valid options:
1. **URN form:** rename serialization to `"urn:nucleus:kind"`. Compatibility: serde rename. Permanent.
2. **URL form:** rename to `"https://nucleus.coproduct.one/claims/kind"`. Self-documenting.

**Recommend (1)** — shorter wire size, IETF-conformant. Document in a `claims.md` reference doc.

**PR.** ~5 LoC + decoder-side update + KAT vector pinning the new name. Bump SVID schema version (informational only — we don't yet have one explicit; tracks under future #34 work).

---

### GAP-8 — No `cnf` confirmation claim (WPT support deferred)

**Severity:** Deferred to v2.

**Why we defer.** WIMSE Workload Proof Token (WPT) binds the token to a specific HTTP request via `cnf` + a separate per-request signature. This is the right answer for high-assurance HTTP APIs but requires:
- DPoP-style nonce handling on the RP side
- A new endpoint shape (`/v1/wpt`) on our OP
- Per-request signing on the pod side, not just per-token

V1 ships bearer-only. WPT lands as a v2 PR after v1 mesh is in production.

**Action.** Document the deferral in `crates/nucleus-oidc-provider/THREAT_MODEL.md` §6 "Out of scope (v1)" — already there as a generic note; expand to mention WPT explicitly.

**PR.** Documentation only, ~10 lines added to threat model out-of-scope section.

---

### GAP-9 — Default issuer URL `nucleus-local://demo` is not HTTPS

**Severity:** Low for `LocalIssuer` (dev-only), HIGH for `JwtIssuer` (#34).

**Where.** `crates/nucleus-lineage/src/local_issuer.rs:64` — default issuer string.

**Why it matters.** RFC 8414 §2 says the `issuer` MUST be a `https://` URL whose path component is `/.well-known/openid-configuration`-resolvable. `nucleus-local://demo` will fail OIDC RP discovery on any compliant client.

**Action.** This is acceptable for `LocalIssuer` because it's dev-only. **For `JwtIssuer` (#34), enforce in the constructor: reject any `issuer` not matching `https://[a-z0-9.-]+(/.*)?`.** This is the conformance teeth for production.

**PR.** Already covered in #34 acceptance criterion (a). Cross-reference here.

---

### GAP-10 — `to_wimse_uri()` and `from_wimse_uri()` not yet implemented

**Severity:** New work (this is the core deliverable of #40).

**Why.** AIMS lets us use `spiffe://…` as a WIMSE identifier verbatim. But:
1. Some RPs (especially those built directly against WIMSE drafts before SPIFFE) expect `wimse://`.
2. Audit logs benefit from emitting both forms so reviewers can grep either way.

**Action.** Add two methods to `CallSpiffeId`:
```rust
impl CallSpiffeId {
    /// Emit the WIMSE URI form. Per AIMS §3, equal to the SPIFFE URI
    /// — the WIMSE identifier MAY be a SPIFFE ID. We return the
    /// SPIFFE form unchanged; callers needing a `wimse://` scheme
    /// alias can post-process.
    pub fn to_wimse_uri(&self) -> &str { self.as_str() }

    /// Accept either `spiffe://…` or `wimse://…`. The latter is
    /// rewritten to `spiffe://` before delegating to `parse`.
    pub fn from_wimse_uri(uri: &str) -> Result<Self, IdError> {
        if let Some(rest) = uri.strip_prefix("wimse://") {
            Self::parse(format!("spiffe://{rest}"))
        } else {
            Self::parse(uri)
        }
    }
}
```

**PR.** ~30 LoC + 4 unit tests (round-trip on both schemes, reject malformed, reject mixed-case scheme).

---

## 3. Required PR list (consolidates GAPs)

| PR | Touches | LoC | Tests | Gates |
|---|---|---|---|---|
| **PR-A** — `typ: at+jwt` header | `local_issuer.rs`, `issuer.rs`, future `crates/nucleus-oidc-provider/` | ~5 | 1 KAT in #49 | Closes GAP-3 |
| **PR-B** — `SvidClaims` extension (`client_id`, `scope`, `act`) | `issuer.rs::SvidClaims`, `local_issuer.rs::fetch_jwt_svid_*` | ~80 | 3 KATs in #49 | Closes GAP-4/5/6 |
| **PR-C** — `nucleus_kind` → `urn:nucleus:kind` | `issuer.rs::SvidClaims`, all decoder call sites | ~10 | 1 KAT pin | Closes GAP-7 |
| **PR-D** — URI cap + FQDN warning | `id.rs` docs, `nucleus-spec` admission validator | ~30 | 2 unit tests | Closes GAP-1, GAP-2 |
| **PR-E** — WIMSE URI methods | `id.rs::CallSpiffeId::{to,from}_wimse_uri` | ~30 | 4 unit tests | Closes GAP-10. Counts toward #40. |
| **PR-F** — Issuer URL HTTPS enforcement | `crates/nucleus-oidc-provider/` (#34) | ~15 | 2 unit tests | Closes GAP-9. Counts toward #34. |
| **PR-G** — Threat model WPT deferral | `crates/nucleus-oidc-provider/THREAT_MODEL.md` §6 | ~10 lines | — | Closes GAP-8 (documentation only) |

**Total:** ~180 LoC + 13 tests across 7 PRs. None are large; PR-B is the only one that touches a struct shape downstream consumers see.

---

## 4. Conformance violations (MUST-level)

Strict MUST-level violations of AIMS or WIMSE that we ship today:

1. **None at the `CallSpiffeId` level.** Our SPIFFE URI is AIMS-conformant per §3 ("MAY be a SPIFFE ID").
2. **`typ: at+jwt` missing** (RFC 9068 §2.1) — required to call our tokens "OAuth 2.0 access tokens." Closing GAP-3 fixes this.

Everything else in the table is a SHOULD or a forward-compatibility addition. We're not in conformance jail; we're slightly behind on RFC 9068 (which AIMS references).

---

## 5. Round-trip property test (acceptance for #40)

Per #40's acceptance criterion (a):

```rust
#[test]
fn wimse_uri_round_trips() {
    let cases = [
        // SPIFFE form (canonical)
        "spiffe://prod.example.com/ns/agents/sa/coder",
        // SPIFFE form with /call/ suffix
        &format!("spiffe://prod.example.com/ns/agents/sa/coder/call/{}/tool/Bash", Uuid::new_v4()),
        // wimse:// scheme alias (rewritten to spiffe:// internally)
        "wimse://prod.example.com/ns/agents/sa/coder",
    ];
    for uri in cases {
        let id = CallSpiffeId::from_wimse_uri(uri).unwrap();
        // Internally always emits spiffe:// — this is the canonical form.
        let round_tripped = CallSpiffeId::from_wimse_uri(id.to_wimse_uri()).unwrap();
        assert_eq!(id, round_tripped);
    }
}
```

Plus: per #40 acceptance (b)/(c), at least one cross-validation KAT from the AIMS draft examples (when -01 publishes a concrete sample token, copy it into `crates/nucleus-oidc-provider/tests/aims_interop.rs` per #49).

---

## 6. Open questions for the implementer of #40

1. **Should `to_wimse_uri()` emit `spiffe://` or `wimse://`?** Both are AIMS-conformant per §3. Recommend `spiffe://` for backwards-compat (existing callers grep for it). Document the choice.

2. **Should `CallSpiffeId` serialize differently based on context (SPIFFE vs WIMSE consumers)?** Recommend NO — the canonical wire form stays SPIFFE; renderers that need WIMSE can post-process. Avoids serde context-sensitivity which has caused real bugs.

3. **Should `MAX_URI_LEN` lower to 2048 to match WIMSE SHOULD?** Recommend NO — keep 4096 with a documented rationale (per-call path depth headroom; well under HTTP / SPIRE socket limits).

4. **Should the FQDN check go on the parser or admission?** Recommend admission (`nucleus-spec` PodSpec validator). Parser stays permissive for backwards-compat with existing dev-mode IDs.

5. **Does `nucleus_kind` rename break existing lineage logs?** Yes — JSONL sinks on disk will mix old (`nucleus_kind`) and new (`urn:nucleus:kind`) records. Recommend decoder accepts both for one release, encoder emits only the new name, document deprecation.

6. **Do we need a `nbf` (not-before) claim?** RFC 7519 says optional. AIMS doesn't mention. Recommend NO for v1 — adds clock-skew surface (T06 in threat model) without observable benefit at our token lifetimes (≤1h).

---

## 7. References

- `draft-klrc-aiagent-auth-00` / `-01` — *AI Agent Authentication and Authorization*
- `draft-ietf-wimse-identifier` — *Workload Identifier*
- `draft-ietf-wimse-arch-07` — *WIMSE Architecture*
- `draft-ietf-wimse-wpt-01` — *Workload Proof Token* (deferred)
- RFC 7519 — JSON Web Token
- RFC 8693 — OAuth 2.0 Token Exchange (especially §4.1 actor chains)
- RFC 8725 — JWT BCP
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens (§2.1 typ, §2.2 claims)
- SPIFFE ID spec §2
- `crates/nucleus-oidc-provider/THREAT_MODEL.md` §T10 — cross-JWT confusion, mitigated by GAP-3 fix
- `docs/oidc-vendor-neutrality-audit.md` — sibling audit (#29)
