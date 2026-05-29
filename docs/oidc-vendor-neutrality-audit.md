# OIDC-Core Vendor-Neutrality Audit (P0.2 / Task #29)

**Date:** 2026-05-28
**Subject:** `nucleus-platform/crates/nucleus-oidc-core/`
**Goal:** Identify which symbols can move into the public, MIT-licensed `crates/nucleus-oidc-core/` in nucleus, which need refactoring before they move, and which must stay in `nucleus-platform` to preserve vendor-neutrality per `nucleus/CLAUDE.md`.
**Scope:** 4 Rust source files + Cargo.toml (~530 LoC total).

---

## 1. Verdict at a glance

| File | Verdict | Lift |
|---|---|---|
| `Cargo.toml` | **(a) Move with edits** | 1 line — rewrite `description`. |
| `src/lib.rs` | **(a) Move with edits** | Rewrite docstrings; drop `pub use federation::*` if (c) splits federation out. |
| `src/error.rs` | **(a) Move with edits** | Rewrite header docstring. Variants are abstract enough. |
| `src/jwks.rs` | **(a) Move with edits** | Rewrite docstrings; add `OKP` (Ed25519) key support (forward-compatible expansion). |
| `src/federation.rs` | **(b) Refactor before move + (c) Keep partly in platform** | The biggest single block of vendor-coupled logic. Structural split required. |

**Bottom line:** ~75% of the crate moves cleanly with docstring scrubs and one signature expansion (`OKP` support in `Jwk::to_decoding_key`). `federation.rs` requires a real refactor — `IssuerKind` becomes registry-driven, vendor URL/prefix constants migrate to the per-provider crates that own them.

---

## 2. File-by-file findings

### 2.1 `Cargo.toml`

```toml
description = "Provider-agnostic OIDC primitives: JWKS resolution,
replay protection, and the shared error type. Used by nucleus-fly-oidc,
nucleus-github-oidc, and any future per-provider validator."
```

**Issue.** `description` names two vendor-specific consumer crates.

**Action.** Rewrite to:
```toml
description = "Provider-agnostic OIDC primitives: JWKS resolution,
replay protection, federation-dispatch hooks, and the shared error
type. Consumed by per-provider validator crates that register their
issuer pattern at startup."
```

**Move-as-of-this:** YES (after rewrite).

---

### 2.2 `src/lib.rs`

**Vendor refs found** (lines 3-4): docstring names `nucleus-fly-oidc`, `nucleus-github-oidc`.

**Issue.** Documentation only; no code-level leakage.

**Action.** Rewrite the module docstring to use abstract terms ("per-provider validator crates that build on this base"). Conditional on the `federation` outcome (§2.5), decide whether `pub mod federation` stays or splits into a `pub trait FederationDispatcher` abstraction.

**Move-as-of-this:** YES (after docstring rewrite + federation decision).

---

### 2.3 `src/error.rs`

**Vendor refs found** (line 2): docstring names `nucleus-fly-oidc`, `nucleus-github-oidc`.

**Variant audit.**

| Variant | Verdict | Note |
|---|---|---|
| `InvalidTokenFormat` | clean | |
| `MissingKeyId` | clean | |
| `UnacceptedAlgorithm(String)` | clean | |
| `UntrustedIssuer(String)` | clean | |
| `OrgNotAllowed(String)` | **borderline** | "Org" is GitHub/Fly terminology. Generalizes acceptably to "namespace within issuer". Keep with neutral docstring. |
| `OrgMismatch { issuer_org, claim_org }` | **borderline** | Same. |
| `AppNotAllowed(String)` | **borderline** | "App" is Fly Machine terminology. Generalizes to "workload identifier within issuer namespace". Keep. |
| `KeyNotFound(String)` | clean | |
| `Jwt(String)` | clean (consider rename → `JwtValidation`) | |
| `TokenReplay(String)` | clean | |
| `Discovery(String)` | clean | |
| `Network(String)` | clean | |
| `InvalidJwks(String)` | clean | |
| `SpiffeId(String)` | clean | |

**Action.** Rewrite header docstring; add abstract documentation to the three "borderline" variants explaining they encode the issuer's intra-issuer subject structure regardless of vendor terminology.

**Move-as-of-this:** YES (after docstring scrub).

---

### 2.4 `src/jwks.rs`

**Vendor refs found.**
- Lines 8-9: docstring "Lifted from `nucleus-fly-oidc/src/jwks.rs`"
- Line 85: comment "the two OIDC providers Nucleus targets (Fly, GitHub) both sign RS256"

**Code-level review.** `KeyResolver` trait, `StaticKeyResolver`, `DiscoveryKeyResolver`, `JtiCache`, `Jwk`, `Jwks` — all structurally vendor-neutral. The `to_decoding_key` matcher (lines 87-104) hard-codes `match self.kty.as_str() { "RSA" => ... }` and rejects anything else. This is a *capability* gap, not a vendor leak — the nucleus OP signs EdDSA (`kty = "OKP"`), so the public crate MUST support OKP. Adding it is a feature, not a scrub.

**Action.**
1. Rewrite both comments.
2. Extend `Jwk::to_decoding_key` to handle `kty == "OKP"` with `crv == "Ed25519"` — required for nucleus-oidc-provider's own JWKS round-trip.
3. Keep existing RSA branch — RP-mode consumers (the future public-crate's role for nucleus-fly-oidc/github-oidc) still need it.
4. Tighten the comment on line 85 to read "any OIDC issuer whose JWKS advertises an unsupported `kty` is rejected explicitly per RFC 8725 §3.3."

**Move-as-of-this:** YES (after docstring scrub + OKP extension).

---

### 2.5 `src/federation.rs` — the major refactor

**Vendor refs found.** This is the file. Every section needs rework:

| Lines | Symbol | Issue |
|---|---|---|
| 5-10 | module docstring | Names "Fly", "GitHub", `nucleus-github-oidc`, `nucleus-fly-oidc` |
| 25 | `IssuerKind` enum doc | "e.g. `Vercel`, `Cloudflare`, `Google`" — names vendors |
| 27-37 | `IssuerKind::GitHub`, `::Fly` | Vendor-named enum variants |
| 28-29, 31-32 | per-variant doc | Hardcodes URLs and per-provider crate names |
| 44-51 | `classify_issuer` body | Hardcoded `"https://token.actions.githubusercontent.com"`, `"https://oidc.fly.io/"` |
| 95-111 | `synthetic_builder_uid` doc | "GitHub-bucket route (`b-gh-{owner}-{repo}`) and Fly identity exchange (`b-fly-{app}`)" |
| 113-130 | `synthetic_builder_uid` body | Match arms emit `"b-gh-"`, `"b-fly-"`, `"b-unknown-"` prefixes |
| 132-248 | tests | All test inputs are vendor URLs / vendor `b-{prefix}-...` shapes |

**Structural problem.** This file conflates three responsibilities:

1. **JWT peek** — base64-decode the payload, parse `iss`. (Vendor-neutral. SALVAGEABLE.)
2. **Issuer classification** — pattern-match `iss` against a known set. (Vendor-coupled by definition.)
3. **Synthetic uid minting** — emit a per-provider stable identifier. (Vendor-coupled by definition.)

(1) belongs in the public crate. (2) and (3) belong *as traits* in the public crate, *with per-vendor implementations* registered by per-provider crates in nucleus-platform.

**Proposed refactor.**

Public-crate (nucleus/crates/nucleus-oidc-core/src/federation.rs):
```rust
/// Trait every per-provider crate implements to register itself with
/// the dispatcher. Static dispatch via a `FederationRegistry` lookup.
pub trait IssuerProvider: Send + Sync + 'static {
    /// Stable name for logging + error messages (e.g. "github", "fly").
    fn name(&self) -> &'static str;
    /// Does this provider claim the given iss?
    fn matches(&self, iss: &str) -> bool;
    /// Per-provider synthetic-uid prefix (e.g. "b-gh-", "b-fly-").
    fn uid_prefix(&self) -> &'static str;
}

/// Registry providers register into at startup.
pub struct FederationRegistry {
    providers: Vec<Box<dyn IssuerProvider>>,
}

impl FederationRegistry {
    pub fn classify(&self, iss: &str) -> Option<&dyn IssuerProvider> { ... }
    pub fn synthetic_uid(&self, iss: &str, scope: &str) -> Option<String> { ... }
}

/// Vendor-neutral JWT peek — moves verbatim.
pub fn peek_jwt_issuer(jwt: &str) -> Result<String, OidcError> { ... }
```

Vendor-coupled (nucleus-platform/crates/nucleus-github-oidc/src/lib.rs):
```rust
pub struct GithubIssuerProvider;
impl IssuerProvider for GithubIssuerProvider {
    fn name(&self) -> &'static str { "github" }
    fn matches(&self, iss: &str) -> bool {
        iss == "https://token.actions.githubusercontent.com"
    }
    fn uid_prefix(&self) -> &'static str { "b-gh-" }
}
```

Same for `FlyIssuerProvider` in `nucleus-fly-oidc`.

**Migration cost.**
- Public crate: ~80 LoC trait + registry + the salvaged `peek_jwt_issuer`.
- nucleus-fly-oidc: ~20 LoC `FlyIssuerProvider` impl + remove dispatch logic from old federation.rs.
- nucleus-github-oidc: ~20 LoC `GithubIssuerProvider` impl + same removal.
- Wire-up site: replace `classify_issuer(iss)` with `registry.classify(iss)` (~10 call sites).
- All existing federation tests stay in nucleus-platform — they're testing per-provider URL patterns.

**Move-as-of-this:** PARTIAL. The trait + registry + `peek_jwt_issuer` move; the vendor `IssuerProvider` impls go to nucleus-platform.

---

## 3. Categorized verdict (per #29 acceptance criteria)

### (a) Safe to move as-is *after docstring scrubs*

- `Cargo.toml` (rewrite `description`)
- `src/lib.rs` (rewrite mod docstring; drop `federation::*` pub uses pending §2.5)
- `src/error.rs` (rewrite header docstring; add doc to borderline variants)
- `src/jwks.rs` (rewrite two comments; **add OKP/Ed25519 branch** to `to_decoding_key` — feature work, not scrub)
- From `src/federation.rs`: `peek_jwt_issuer`, `IssuerPeek` (private), `peek_and_classify` *trait-version* (new wrapper returning `Option<&dyn IssuerProvider>`)

### (b) Symbols requiring rename/abstraction before move

- `IssuerKind` enum → `IssuerProvider` trait (`name()`, `matches()`, `uid_prefix()` methods)
- `classify_issuer(iss: &str) -> IssuerKind` → `FederationRegistry::classify(iss: &str) -> Option<&dyn IssuerProvider>`
- `synthetic_builder_uid(IssuerKind, &str)` → `FederationRegistry::synthetic_uid(iss, scope)` *or* `provider.synthetic_uid(scope)` method

### (c) Must stay in nucleus-platform (vendor-specific)

- All vendor URL constants (`"https://token.actions.githubusercontent.com"`, `"https://oidc.fly.io/"`)
- All vendor synthetic-uid prefixes (`"b-gh-"`, `"b-fly-"`)
- All vendor `IssuerKind::GitHub`, `IssuerKind::Fly` references — replaced by per-provider crate `IssuerProvider` impls
- Vendor-specific tests in `federation.rs`

---

## 4. CI gate proposal

The grep patterns below are wired into `ci/no-vendor-strings.sh`. Run on every PR touching `crates/nucleus-oidc-{provider,core}/`. Allow-list mechanism documented in script header.

```regex
# Vendor crate names
nucleus-(fly|github|anthropic|openai|google|vercel|cloudflare)-(oidc|tool|wif)

# Vendor product / company names
\b(fly\.?io|flyio)\b
\b(github(-?actions?)?|gh-?actions?)\b
\b(anthropic|claude(-?code)?|sonnet|opus|haiku)\b
\b(openai|gpt-?\d|chatgpt|davinci|whisper)\b
\b(gemini|bard|google-?ai|vertex-?ai)\b
\b(vercel|cloudflare|fastly)\b
\b(aws|amazon|gcp|azure)\b  # cloud vendors — flag for context
\b(stripe|paddle|adyen)\b  # billing vendors

# Vendor hostnames + paths
https?://([a-z0-9-]+\.)*(fly\.io|fly\.dev|github\.com|githubusercontent\.com|anthropic\.com|openai\.com|googleusercontent\.com)

# Vendor token-prefix patterns
\bsk-(ant|or|live|test)-[A-Za-z0-9_]+\b
\bgh[ps]_[A-Za-z0-9]+\b
\bxoxb-[0-9-]+-[A-Za-z0-9]+\b

# Vendor-coupled synthetic-uid prefixes (internal nucleus-platform convention)
\bb-(gh|fly|anthropic|openai)-
```

**Allow-list mechanism.** A grep match on a line is permitted if the same line carries the comment `// vendor-allow: <reason>`. Reviewer enforces that the reason is genuine (e.g., negative test, RFC quote, threat-model attacker example).

---

## 5. Deliverables this audit produces

- ✅ This document — `docs/oidc-vendor-neutrality-audit.md`
- ✅ CI gate prototype — `ci/no-vendor-strings.sh` (next section)
- ⏭️ Implementation handoff to **#38** (P2.1 — Move nucleus-oidc-core into public nucleus). This audit is the input spec; #38 executes the move + refactor + adds the OKP key support called out in §2.4.
- ⏭️ Test-suite handoff to **#54** (P5.2 — CI gate). The grep patterns above land in `ci/no-vendor-strings.sh` and run on every PR.

---

## 6. Open questions for the implementer of #38

1. **Should `IssuerProvider` registration be compile-time (via inventory crate / linkme) or runtime (explicit `registry.register(Box::new(...))` calls)?** Runtime is cleaner for testing but compile-time guarantees no provider is silently missing in production. Recommend runtime in v1; revisit if registration-omission bugs appear.

2. **Does `OidcError::OrgMismatch` survive the move, or split into `OidcError::IssuerClaimMismatch { dimension, expected, actual }`?** The latter is more general but breaks downstream pattern-matching. Recommend keeping as-is and documenting the generalization.

3. **Should the trait method `synthetic_uid(scope: &str) -> String` move onto `IssuerProvider`, or stay as a registry method that looks up the prefix?** On the trait is more idiomatic; on the registry centralizes uniqueness checking (no two providers claim the same prefix). Recommend on the registry, with a `register_unique_prefix` assertion at registration.

4. **Does `Jwk::to_decoding_key` need `EC` (P-256/P-384) support, or only `RSA` + `OKP`?** None of our current consumers use EC. Recommend adding `EC` only when a real consumer needs it; document as a known gap.

5. **What's the deprecation policy for `nucleus-platform/crates/nucleus-oidc-core/`?** Two options: (i) delete and update all callers in one PR (atomic, churns more files); (ii) leave as `pub use nucleus_oidc_core::*` shim for one release, then delete. Recommend (i) for atomicity — the move is small enough to fit in one PR.

---

## 7. References

- `nucleus/CLAUDE.md` — vendor-neutrality rules
- `crates/nucleus-oidc-provider/THREAT_MODEL.md` (#28) — T05 federation misconfig + T11 discovery tampering bear on the dispatch path
- RFC 8725 §3.3 — explicit-reject on unsupported algorithms
- IANA JWA registry — `kty` values (RSA, EC, OKP) — informs the §2.4 expansion
