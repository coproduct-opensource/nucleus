//! Aeneas-extractable decision core of JWT-SVID claims validation.
//!
//! The control plane's `verify_jwt_svid`
//! (`crates/nucleus-control-plane-server/src/auth.rs`) is two things glued
//! together: an EdDSA signature check over the compact-JWS input, and a pure
//! decision over the decoded claims (`exp`/`nbf` against the clock with skew
//! leeway, `aud` membership, `sub` prefix). The signature half is
//! `ed25519-dalek` and is outside Aeneas's extractable subset (#2452's
//! toolchain check). The decision half is pure, and THIS module is its
//! `String`/iterator-free restatement so the reachable subgraph stays inside
//! the Charon/Aeneas safe-Rust subset:
//!
//! - subject, prefix and audience values are `&[u8]`; equality and prefix
//!   are index-driven `while` loops ([`bytes_eq`], [`has_prefix`]);
//! - the temporal + membership decision is a straight-line function
//!   ([`decide_claims`]) whose check ORDER is the production order, so the
//!   verdict a caller maps back to `AuthError` is the same one production
//!   would have raised first.
//!
//! # The scope boundary (what stays in production, and why)
//!
//! The audience check is `auds.iter().any(|a| a == allowed)`. Its *fold* is
//! not extracted: a slice of audiences is `&[&[u8]]`, a nested borrow, which
//! Aeneas rejects outright ("unsupported nested borrows"), and the
//! `Iterator::any` it would replace is exactly the fold Aeneas emits as an
//! opaque external axiom. So production keeps the one-line fold and applies
//! the extracted [`bytes_eq`] per element; the extracted [`decide_claims`]
//! receives the fold's result as `aud_ok`. The theorems below are therefore
//! about the decision given membership, not about the membership loop.
//!
//! # Where it is hosted, and why
//!
//! The control plane owns the function; this crate owns the only
//! OIDC-family Aeneas pipeline (`.github/workflows/aeneas-oidc-spiffe.yml`,
//! `lean/`). Hosting the core here reuses that pipeline unchanged rather than
//! standing up a second one, and the control plane depends on this crate for
//! the core alone. The generated Lean lands in
//! `lean/generated/NucleusGithubOidc/` beside the SPIFFE derivation slice, and
//! the theorems live in `lean/JwtSvidClaimsProofs.lean`.
//!
//! # Faithfulness (the honest trust chain)
//!
//! - **Call-through.** Production `verify_jwt_svid` CALLS [`decide_claims`]
//!   (with [`has_prefix`] and per-element [`bytes_eq`]) for its claims
//!   decision; it does not keep a parallel copy. The theorems are about the
//!   live path, not a mirror of it.
//! - **Parity oracle.** The `#[cfg(test)]` block below carries the pre-refactor
//!   inline clause lifted verbatim as `production_claims_check`, and proptests
//!   that the composed call ([`claims_verdict`], the exact expression
//!   production evaluates) agrees with it on random claims, clocks, skews,
//!   audience lists and subjects — the guard that the refactor changed
//!   nothing.
//! - **Overflow.** Production computes `exp + skew` and `now + skew` with
//!   plain `+`. The core keeps the same expressions; the Aeneas translation
//!   makes overflow an explicit `fail`, and the Lean theorems are stated
//!   under the no-overflow hypothesis they surface. The parity generators
//!   stay below `u64::MAX / 2` for the same reason.
//!
//! # What the Lean side proves (over the GENERATED defs, never a hand model)
//!
//! - **Soundness:** `decide_claims … = ok Admit` implies every predicate held:
//!   `now ≤ exp + skew`, `nbf ≤ now + skew` when present, `aud_ok`, `sub_ok`.
//!   No admission without all four.
//! - **Fail-closed:** `aud_ok = false` or `sub_ok = false` never yields
//!   `Admit`, whatever the clock says.
//! - **Completeness:** when all four hold the verdict is `Admit`, so the core
//!   cannot reject a valid token either.
//! - **Verdict attribution:** `NotYetValid` is only ever raised with
//!   `nbf = Some`, which is what lets the caller report the `nbf` it refused.
//!
//! The extraction roots live here so the CI extractor can name them with
//! `charon … --start-from nucleus_github_oidc::extracted::jwt_svid_claims::<fn>`.

/// Outcome of the pure claims decision, in production's check order.
///
/// The control plane maps each variant onto the `AuthError` it raised before
/// the core existed (`Expired` / `NotYetValid` → 401, the two mismatches →
/// 403). `Admit` is the only variant that admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimsVerdict {
    /// Every claims predicate held.
    Admit,
    /// `exp + skew < now`.
    Expired,
    /// `nbf` present and `nbf > now + skew`.
    NotYetValid,
    /// No `aud` entry equals the configured audience.
    AudienceMismatch,
    /// `sub` does not start with the configured prefix.
    SubjectPrefixMismatch,
}

/// Byte-slice equality as an index loop (`a == b` on `&[u8]`).
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0usize;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `s.starts_with(prefix)` on byte slices, as an index loop.
pub fn has_prefix(s: &[u8], prefix: &[u8]) -> bool {
    if prefix.len() > s.len() {
        return false;
    }
    let mut i = 0usize;
    while i < prefix.len() {
        if s[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The straight-line claims decision, in production's check order:
/// expiry, then not-before, then audience, then subject prefix.
///
/// `aud_ok` is the audience fold's result (production: `any(bytes_eq)`),
/// `sub_ok` is [`has_prefix`]. Arithmetic is the production `exp + skew` /
/// `now + skew`; overflow is a `fail` in the extraction and a panic-or-wrap
/// in Rust exactly as it was before the refactor.
pub fn decide_claims(
    exp: u64,
    nbf: Option<u64>,
    now: u64,
    skew: u64,
    aud_ok: bool,
    sub_ok: bool,
) -> ClaimsVerdict {
    if exp + skew < now {
        return ClaimsVerdict::Expired;
    }
    let not_yet_valid = match nbf {
        Some(n) => n > now + skew,
        None => false,
    };
    if not_yet_valid {
        return ClaimsVerdict::NotYetValid;
    }
    if !aud_ok {
        return ClaimsVerdict::AudienceMismatch;
    }
    if !sub_ok {
        return ClaimsVerdict::SubjectPrefixMismatch;
    }
    ClaimsVerdict::Admit
}

/// The exact composition production evaluates: the audience fold over
/// [`bytes_eq`], [`has_prefix`] on the subject, then [`decide_claims`].
///
/// NOT an extraction root (the `&[&[u8]]` parameter is a nested borrow, see
/// the module docs); it exists so the control plane and the parity oracle
/// call one definition of the composition.
#[allow(clippy::too_many_arguments)]
pub fn claims_verdict(
    exp: u64,
    nbf: Option<u64>,
    now: u64,
    skew: u64,
    auds: &[&[u8]],
    want_aud: &[u8],
    sub: &[u8],
    prefix: &[u8],
) -> ClaimsVerdict {
    let aud_ok = auds.iter().any(|a| bytes_eq(a, want_aud));
    let sub_ok = has_prefix(sub, prefix);
    decide_claims(exp, nbf, now, skew, aud_ok, sub_ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The pre-refactor claims clause of `verify_jwt_svid`
    /// (`nucleus-control-plane-server/src/auth.rs`), lifted verbatim as the
    /// parity oracle. Returns the verdict production would have mapped to an
    /// `AuthError`, in production's order.
    #[allow(clippy::too_many_arguments)]
    fn production_claims_check(
        exp: u64,
        nbf: Option<u64>,
        now: u64,
        clock_skew_secs: u64,
        auds: &[String],
        allowed_audience: &str,
        sub: &str,
        allowed_subject_prefix: &str,
    ) -> ClaimsVerdict {
        if exp + clock_skew_secs < now {
            return ClaimsVerdict::Expired;
        }
        if let Some(nbf) = nbf
            && nbf > now + clock_skew_secs
        {
            return ClaimsVerdict::NotYetValid;
        }
        if !auds.iter().any(|a| a == allowed_audience) {
            return ClaimsVerdict::AudienceMismatch;
        }
        if !sub.starts_with(allowed_subject_prefix) {
            return ClaimsVerdict::SubjectPrefixMismatch;
        }
        ClaimsVerdict::Admit
    }

    #[test]
    fn loops_agree_with_std_on_edge_cases() {
        assert!(bytes_eq(b"", b""));
        assert!(!bytes_eq(b"a", b""));
        assert!(!bytes_eq(b"ab", b"ac"));
        assert!(has_prefix(b"spiffe://td/x", b"spiffe://td/"));
        assert!(has_prefix(b"x", b""));
        assert!(!has_prefix(b"", b"x"));
    }

    #[test]
    fn verdict_order_is_production_order() {
        // Every predicate false at once: expiry wins, then nbf, then aud, then sub.
        assert_eq!(
            decide_claims(0, Some(u64::MAX / 4), 100, 0, false, false),
            ClaimsVerdict::Expired
        );
        assert_eq!(
            decide_claims(200, Some(u64::MAX / 4), 100, 0, false, false),
            ClaimsVerdict::NotYetValid
        );
        assert_eq!(
            decide_claims(200, Some(50), 100, 0, false, false),
            ClaimsVerdict::AudienceMismatch
        );
        assert_eq!(
            decide_claims(200, Some(50), 100, 0, true, false),
            ClaimsVerdict::SubjectPrefixMismatch
        );
        assert_eq!(
            decide_claims(200, None, 100, 0, true, true),
            ClaimsVerdict::Admit
        );
        // Skew leeway on both edges, exactly as production applies it.
        assert_eq!(
            decide_claims(90, None, 100, 10, true, true),
            ClaimsVerdict::Admit
        );
        assert_eq!(
            decide_claims(89, None, 100, 10, true, true),
            ClaimsVerdict::Expired
        );
        assert_eq!(
            decide_claims(200, Some(110), 100, 10, true, true),
            ClaimsVerdict::Admit
        );
        assert_eq!(
            decide_claims(200, Some(111), 100, 10, true, true),
            ClaimsVerdict::NotYetValid
        );
    }

    proptest! {
        /// PARITY: the byte loops agree with `==` / `starts_with` on random
        /// strings, including arbitrary Unicode.
        #[test]
        fn loops_match_std(a in r"\PC{0,16}", b in r"\PC{0,16}") {
            prop_assert_eq!(bytes_eq(a.as_bytes(), b.as_bytes()), a == b);
            prop_assert_eq!(has_prefix(a.as_bytes(), b.as_bytes()), a.starts_with(&b));
        }

        /// PARITY: the composed decision equals the pre-refactor production
        /// clause across random claims, clocks and skews. Values stay below
        /// `u64::MAX / 2` so `exp + skew` / `now + skew` cannot overflow
        /// (production would panic or wrap there; see module docs).
        #[test]
        fn claims_verdict_matches_production(
            exp in 0u64..(u64::MAX / 2),
            nbf in prop::option::of(0u64..(u64::MAX / 2)),
            now in 0u64..(u64::MAX / 2),
            skew in 0u64..4096u64,
            auds in prop::collection::vec("[a-z:/.]{0,12}", 0..4),
            want in "[a-z:/.]{0,12}",
            sub in "[a-z:/.]{0,16}",
            prefix in "[a-z:/.]{0,8}",
        ) {
            let refs: Vec<&[u8]> = auds.iter().map(|s| s.as_bytes()).collect();
            let extracted = claims_verdict(exp, nbf, now, skew, &refs, want.as_bytes(), sub.as_bytes(), prefix.as_bytes());
            let production = production_claims_check(exp, nbf, now, skew, &auds, &want, &sub, &prefix);
            prop_assert_eq!(extracted, production);
        }

        /// PARITY, dense: the same with clocks clustered around `exp`/`nbf`
        /// so the skew edges are actually exercised.
        #[test]
        fn claims_verdict_matches_production_near_edges(
            exp in 1_000u64..2_000u64,
            nbf in prop::option::of(1_000u64..2_000u64),
            now in 900u64..2_100u64,
            skew in 0u64..128u64,
            aud_ok in any::<bool>(),
            sub_ok in any::<bool>(),
        ) {
            let auds: Vec<String> = if aud_ok { vec!["x".into(), "aud".into()] } else { vec!["x".into()] };
            let sub = if sub_ok { "spiffe://td/ok" } else { "spiffe://other/ok" };
            let refs: Vec<&[u8]> = auds.iter().map(|s| s.as_bytes()).collect();
            let extracted = claims_verdict(exp, nbf, now, skew, &refs, b"aud", sub.as_bytes(), b"spiffe://td/");
            let production = production_claims_check(exp, nbf, now, skew, &auds, "aud", sub, "spiffe://td/");
            prop_assert_eq!(extracted, production);
        }
    }
}
