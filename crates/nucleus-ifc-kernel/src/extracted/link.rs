//! Links between pods (ADR 0017): the decisions, as the slice Charon→Aeneas
//! translates to Lean.
//!
//! # What is extracted here, and what is not
//!
//! Extracted (real code, translated by Aeneas): the **per-decision predicates**:
//! whether a link may be made ([`may_link`]), unmade ([`may_unlink`]), whether a
//! pod may be cancelled while links name it ([`may_cancel`]), whether a link
//! carries a connection ([`link_matches`]) or names a pod ([`names`]), and
//! whether one request over a live connection is delivered ([`may_deliver`]).
//!
//! **Not** extracted: the table itself, a list of links and connections. As in
//! [`super::egress`], every function here is scalar-only, because Aeneas emits
//! most collection operations as opaque axioms. The list semantics (a connection
//! rides a link in the table; unlink severs; exit drops) is stated in Lean over
//! `List`, in `LinkTable.lean`, and `LinkTableExtracted.lean` proves those
//! definitions agree with the functions below. The Rust table that applies them,
//! `crate::links::LinkTable`, is held to the Lean transitions by tests named
//! after the theorems.
//!
//! # Identifiers
//!
//! A pod id is its UUID as a `u128`. A trust domain is compared before the call
//! (`same_trust_domain`): a string comparison is not scalar, and what the proof
//! needs is only that the two are equal.

/// A row of the link table: `src` may open connections to `port` on `dst`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Link {
    pub src: u128,
    pub dst: u128,
    /// The destination's listening port, as the source's relay names it.
    pub port: u32,
}

/// Whether `link` is the row `(src, dst, port)`.
pub fn link_matches(link: Link, src: u128, dst: u128, port: u32) -> bool {
    link.src == src && link.dst == dst && link.port == port
}

/// Whether `link` names `pod` at either end.
pub fn names(link: Link, pod: u128) -> bool {
    link.src == pod || link.dst == pod
}

/// Whether a link `src → dst` may be made.
///
/// Every conjunct is a refusal reason the ADR names: the caller must manage both
/// ends (§2; a non-owner is answered 404, never told which end failed); a pod
/// is not linked to itself; both ends share one trust domain (ADR 0001; a link
/// across tenants needs a delegation, out of v1); the row is not already there.
pub fn may_link(
    manages_src: bool,
    manages_dst: bool,
    same_trust_domain: bool,
    src: u128,
    dst: u128,
    present: bool,
) -> bool {
    manages_src && manages_dst && src != dst && same_trust_domain && !present
}

/// Whether a link may be unmade: it is in the table, and the caller manages its
/// source.
pub fn may_unlink(present: bool, manages_src: bool) -> bool {
    present && manages_src
}

/// Whether an API cancel may remove a pod: the caller manages it and no link
/// names it (§4). A linked pod is answered 409 until its links go.
pub fn may_cancel(manages: bool, linked: bool) -> bool {
    manages && !linked
}

/// Whether one request over a connection is delivered: the connection is live
/// and the host's pod policy admitted this request (§1; ADR 0014, 0015). Split
/// from the connect decision so a live connection is never read as "passes".
pub fn may_deliver(connection_live: bool, host_admits: bool) -> bool {
    connection_live && host_admits
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u128 = 0x1111;
    const B: u128 = 0x2222;

    fn link() -> Link {
        Link {
            src: A,
            dst: B,
            port: 8080,
        }
    }

    /// Each conjunct of `may_link` refuses on its own: drop any one guard and
    /// one of these fails.
    #[test]
    fn every_guard_of_may_link_refuses_alone() {
        assert!(may_link(true, true, true, A, B, false));
        assert!(
            !may_link(false, true, true, A, B, false),
            "caller must manage src"
        );
        assert!(
            !may_link(true, false, true, A, B, false),
            "caller must manage dst"
        );
        assert!(
            !may_link(true, true, false, A, B, false),
            "one trust domain"
        );
        assert!(!may_link(true, true, true, A, A, false), "no self link");
        assert!(!may_link(true, true, true, A, B, true), "no duplicate row");
    }

    #[test]
    fn a_link_matches_only_its_own_row() {
        let l = link();
        assert!(link_matches(l, A, B, 8080));
        assert!(!link_matches(l, B, A, 8080), "direction matters");
        assert!(!link_matches(l, A, B, 8081), "port matters");
    }

    #[test]
    fn names_is_either_end() {
        let l = link();
        assert!(names(l, A) && names(l, B));
        assert!(!names(l, 0x3333));
    }

    #[test]
    fn cancel_unlink_and_delivery_guards() {
        assert!(may_cancel(true, false));
        assert!(!may_cancel(true, true), "a linked pod is not cancelled");
        assert!(!may_cancel(false, false));
        assert!(may_unlink(true, true));
        assert!(!may_unlink(false, true) && !may_unlink(true, false));
        assert!(may_deliver(true, true));
        assert!(!may_deliver(true, false), "a live connection is not a pass");
        assert!(!may_deliver(false, true));
    }
}
