//! The Aeneas-extractable OIDC→SPIFFE slice: byte classifier, segment
//! sanitizer, and SPIFFE-path renderer — all `String`/iterator/`format!`-free.
//!
//! See [`super`] (module docs) for the trust chain and the lossiness/collision
//! finding. Every function here is bound to the production code in `claims.rs`
//! by the parity proptests at the bottom of this file.

/// SPIFFE path segments only allow `[A-Za-z0-9._-]`. This is the *exact*
/// charset clause of the production `sanitize_segment` (`claims.rs`), written
/// as a pure byte comparison rather than `char::is_ascii_alphanumeric() || …`
/// so Aeneas emits a translated body (no opaque `char` method axiom).
///
/// `0x30..=0x39` = `0-9`, `0x41..=0x5A` = `A-Z`, `0x61..=0x7A` = `a-z`,
/// `0x2E` = `.`, `0x5F` = `_`, `0x2D` = `-`.
///
/// Deliberately written as `>=`/`<=` comparisons, NOT `RangeInclusive::contains`
/// (which clippy suggests): a `.contains()` method call is emitted by Aeneas as
/// an opaque external axiom, which would land an unspecified comparison axiom on
/// the proof's critical path. Plain comparisons translate to a `def` body the
/// `#print axioms` audit stays clean over (mirrors the portcullis `irank`
/// rationale).
#[allow(clippy::manual_range_contains)]
pub fn is_spiffe_byte(b: u8) -> bool {
    (b >= 0x30 && b <= 0x39)
        || (b >= 0x41 && b <= 0x5A)
        || (b >= 0x61 && b <= 0x7A)
        || b == 0x2E
        || b == 0x5F
        || b == 0x2D
}

/// The dash byte (`-`, `0x2D`) the sanitizer collapses runs into and trims.
const DASH: u8 = 0x2D;

/// Byte-indexed mirror of the production `sanitize_segment` (`claims.rs`).
///
/// Behavior, identical to production:
/// 1. Walk the input bytes left to right. An allowed byte ([`is_spiffe_byte`])
///    is copied through; any run of disallowed bytes collapses to a single
///    `-` (tracked by `prev_dash`).
/// 2. Trim every leading and trailing `-`.
///
/// This is byte-EQUIVALENT to the production `char`-loop because the allowed
/// set is ASCII-only: a multi-byte UTF-8 char is a run of disallowed bytes and
/// collapses to one `-`, exactly as the whole char would. (Proven across random
/// Unicode by `sanitize_bytes_matches_production` below.)
///
/// Written with a `while` loop over `&[u8]` + a `Vec<u8>` accumulator — both
/// inside the Charon/Aeneas safe-Rust subset (unlike `str::chars()`).
pub fn sanitize_bytes(input: &[u8]) -> Vec<u8> {
    // Phase 1: collapse disallowed runs to a single dash.
    let mut collapsed: Vec<u8> = Vec::new();
    let mut prev_dash: bool = false;
    let mut i: usize = 0;
    let n: usize = input.len();
    while i < n {
        let b: u8 = input[i];
        if is_spiffe_byte(b) {
            collapsed.push(b);
            prev_dash = b == DASH;
        } else {
            if !prev_dash {
                collapsed.push(DASH);
            }
            prev_dash = true;
        }
        i += 1;
    }

    // Phase 2: trim leading dashes (find first non-dash index `lo`).
    let m: usize = collapsed.len();
    let mut lo: usize = 0;
    while lo < m && collapsed[lo] == DASH {
        lo += 1;
    }
    // Trim trailing dashes (find one-past-last non-dash index `hi`).
    let mut hi: usize = m;
    while hi > lo && collapsed[hi - 1] == DASH {
        hi -= 1;
    }
    // Copy the trimmed window [lo, hi).
    let mut out: Vec<u8> = Vec::new();
    let mut k: usize = lo;
    while k < hi {
        out.push(collapsed[k]);
        k += 1;
    }
    out
}

/// Append all of `src` onto `dst` (a `Vec<u8>` `push_str`-equivalent that stays
/// in the byte/`Vec` subset — no `&str`/`format!`).
fn append(dst: &mut Vec<u8>, src: &[u8]) {
    let mut i: usize = 0;
    let n: usize = src.len();
    while i < n {
        dst.push(src[i]);
        i += 1;
    }
}

/// Render the SPIFFE path
/// `spiffe://{td}/ns/github/sa/{owner}/{repo}/refs/{ref}` from ALREADY-SANITIZED
/// owner / repo / ref segments and the trust-domain bytes — the `format!` in
/// production `derive_spiffe_id`, rewritten as manual `Vec<u8>` concatenation.
///
/// The literals are spelled as byte arrays so no `&str`/`format!` machinery is
/// reachable. Equivalence to the production `format!` is proven by
/// `derive_spiffe_bytes_matches_production` below.
///
/// NOTE: this is the *rendering* step only. The production `derive_spiffe_id`
/// additionally (a) parses `repository` into `(owner, repo)`, (b) enforces
/// `repository_owner == owner`, (c) rejects empty post-sanitization segments,
/// and (d) runs `CallSpiffeId::parse`. Those guards live in production
/// `derive_spiffe_id` around this renderer and are NOT re-extracted: (b)/(c)
/// are simple equality / emptiness checks and (d) is the lineage parser (out of
/// subset). They are out of scope for the Lean theorems (see `lean/README.md`).
pub fn derive_spiffe_bytes(
    trust_domain: &[u8],
    owner_sanitized: &[u8],
    repo_sanitized: &[u8],
    ref_sanitized: &[u8],
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    // "spiffe://"
    append(
        &mut out,
        &[0x73, 0x70, 0x69, 0x66, 0x66, 0x65, 0x3A, 0x2F, 0x2F],
    );
    append(&mut out, trust_domain);
    // "/ns/github/sa/"
    append(
        &mut out,
        &[
            0x2F, 0x6E, 0x73, 0x2F, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2F, 0x73, 0x61, 0x2F,
        ],
    );
    append(&mut out, owner_sanitized);
    // "/"
    out.push(0x2F);
    append(&mut out, repo_sanitized);
    // "/refs/"
    append(&mut out, &[0x2F, 0x72, 0x65, 0x66, 0x73, 0x2F]);
    append(&mut out, ref_sanitized);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The production `sanitize_segment`, lifted out of `claims.rs` verbatim so
    /// the proptest can compare against the EXACT shipped logic. (It is private
    /// in `claims.rs`; this is a byte-for-byte copy of that function body, used
    /// only as the parity oracle.)
    fn production_sanitize_segment(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut prev_dash = false;
        for ch in input.chars() {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
                out.push(ch);
                prev_dash = ch == '-';
            } else {
                if !prev_dash {
                    out.push('-');
                }
                prev_dash = true;
            }
        }
        out.trim_matches('-').to_string()
    }

    /// The production `format!` render, lifted verbatim from `derive_spiffe_id`
    /// (`claims.rs`) — the parity oracle for [`derive_spiffe_bytes`].
    fn production_render(td: &str, owner: &str, repo: &str, r#ref: &str) -> String {
        format!("spiffe://{td}/ns/github/sa/{owner}/{repo}/refs/{}", r#ref)
    }

    #[test]
    fn is_spiffe_byte_matches_production_charset() {
        // EXHAUSTIVE over all 256 byte values: the byte predicate equals the
        // production char clause for every single-byte (ASCII) value.
        for b in 0u8..=255 {
            let want = (b as char).is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-';
            assert_eq!(is_spiffe_byte(b), want, "charset drift at byte {b:#04x}");
        }
    }

    proptest! {
        /// PARITY: the extracted byte sanitizer is byte-identical to the
        /// production `char` sanitizer across random strings, INCLUDING
        /// arbitrary Unicode (`\\PC*` = any chars). This is the proof that the
        /// byte-loop rewrite is behavior-preserving.
        #[test]
        fn sanitize_bytes_matches_production(s in r"\PC*") {
            let extracted = sanitize_bytes(s.as_bytes());
            let production = production_sanitize_segment(&s);
            prop_assert_eq!(
                extracted,
                production.into_bytes(),
                "sanitize parity drift for input {:?}",
                s
            );
        }

        /// PARITY: the extracted renderer produces the SAME path bytes as the
        /// production `format!`, across random already-sanitized-ish segments.
        #[test]
        fn derive_spiffe_bytes_matches_production(
            td in "[a-z0-9.]{1,20}",
            owner in r"[A-Za-z0-9._-]{1,20}",
            repo in r"[A-Za-z0-9._-]{1,20}",
            rf in r"[A-Za-z0-9._-]{1,40}",
        ) {
            let extracted = derive_spiffe_bytes(
                td.as_bytes(),
                owner.as_bytes(),
                repo.as_bytes(),
                rf.as_bytes(),
            );
            let production = production_render(&td, &owner, &repo, &rf);
            prop_assert_eq!(extracted, production.into_bytes());
        }

        /// IDEMPOTENCE (Rust-side corroboration of the Lean theorem): sanitizing
        /// an already-sanitized output is a no-op.
        #[test]
        fn sanitize_idempotent(s in r"\PC*") {
            let once = sanitize_bytes(s.as_bytes());
            let twice = sanitize_bytes(&once);
            prop_assert_eq!(once, twice);
        }

        /// CHARSET + no leading/trailing dash (Rust-side corroboration of the
        /// Lean `sanitize_charset` theorem). NOTE: we deliberately do NOT claim
        /// "no `--` run" — production does not guarantee it. A literal `-` in
        /// the input adjacent to a collapsed disallowed-run dash yields `--`
        /// (e.g. `"a𖭐-A"` → `"a--A"`; production's own test pins
        /// `sanitize_segment("a---b") == "a---b"`). The only invariant the trim
        /// gives is no LEADING/TRAILING dash; that is what we prove.
        #[test]
        fn sanitize_output_wellformed(s in r"\PC*") {
            let out = sanitize_bytes(s.as_bytes());
            // every byte allowed
            for &b in &out {
                prop_assert!(is_spiffe_byte(b), "disallowed byte {b:#04x} in output");
            }
            if !out.is_empty() {
                prop_assert_ne!(out[0], DASH, "leading dash");
                prop_assert_ne!(out[out.len() - 1], DASH, "trailing dash");
            }
        }
    }

    // ── The collision finding (lossiness ⇒ NOT injective) ────────────────────

    /// PINNED COUNTEREXAMPLE (the honest finding): two DISTINCT git refs that
    /// sanitize to the SAME segment, hence derive the SAME SPIFFE id within one
    /// owner/repo. `refs/heads/x` and `refs-heads-x` both → `refs-heads-x`.
    /// A SPIFFE-id collision is an authz-confusion surface: a token minted by
    /// the real branch `heads/x` and one minted by a (hypothetical) branch
    /// literally named `heads-x` would render the same downstream identity.
    /// Pinned so a future "we made it injective" change is caught.
    #[test]
    fn collision_distinct_refs_same_spiffe_id() {
        let a = sanitize_bytes(b"refs/heads/x");
        let b = sanitize_bytes(b"refs-heads-x");
        assert_ne!(b"refs/heads/x".to_vec(), b"refs-heads-x".to_vec());
        assert_eq!(a, b, "distinct refs must collide under lossy sanitize");
        assert_eq!(a, b"refs-heads-x".to_vec());

        // And the full derived paths collide too (same owner/repo/td).
        let path_a = derive_spiffe_bytes(
            b"nucleus.io",
            b"org",
            b"r",
            &sanitize_bytes(b"refs/heads/x"),
        );
        let path_b = derive_spiffe_bytes(
            b"nucleus.io",
            b"org",
            b"r",
            &sanitize_bytes(b"refs-heads-x"),
        );
        assert_eq!(path_a, path_b);
    }

    /// A second, owner/repo-axis collision: `a/b` vs `a-b` (the module-doc
    /// example). Distinct repo strings, same sanitized segment.
    #[test]
    fn collision_distinct_repo_segments() {
        assert_eq!(sanitize_bytes(b"a/b"), sanitize_bytes(b"a-b"));
        assert_eq!(sanitize_bytes(b"a/b"), b"a-b".to_vec());
    }
}
