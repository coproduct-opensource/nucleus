//! TLS termination (ADR 0015 E3, used by ADR 0017 links): the decision on one
//! terminated handshake, as the slice Charon→Aeneas translates to Lean.
//!
//! `TlsTermination.lean` states the meaning (a per-pod CA whose key only the
//! pod's proxy holds; leaves only for permitted names, never past the CA's
//! deadline; SNI must equal `Host`; a client that rejects the leaf is refused,
//! never tunnelled). `TlsTerminationExtracted.lean` proves [`tls_verdict`]
//! computes exactly the outcome `TlsTermination.step` journals for a handshake.
//!
//! The order of the checks is the model's, and it matters for what is recorded:
//! an expired CA is reported before anything about the name, so a late
//! handshake never reveals which names the pod may reach.

/// How one terminated exchange ends. There is no opaque outcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TlsVerdict {
    /// The request goes on to the per-request decision (ADR 0015 §2).
    Decided,
    /// No live CA for the pod, or past its deadline.
    RefusedExpired,
    /// The SNI name is outside the CA's name constraints.
    RefusedNameNotPermitted,
    /// The client did not accept the leaf (a pinned client, or one that trusts
    /// another pod's CA): `client_rejected_interception`.
    RefusedClientRejected,
    /// SNI and `Host` differ: domain fronting.
    RefusedFronting,
}

/// The verdict for one handshake.
///
/// `now` and `not_after` are seconds; the comparison cannot fail, so the
/// extracted definition carries no side condition.
pub fn tls_verdict(
    ca_live: bool,
    now: u64,
    not_after: u64,
    name_permitted: bool,
    client_accepted_leaf: bool,
    sni_matches_host: bool,
) -> TlsVerdict {
    if !ca_live || now > not_after {
        return TlsVerdict::RefusedExpired;
    }
    if !name_permitted {
        return TlsVerdict::RefusedNameNotPermitted;
    }
    if !client_accepted_leaf {
        return TlsVerdict::RefusedClientRejected;
    }
    if !sni_matches_host {
        return TlsVerdict::RefusedFronting;
    }
    TlsVerdict::Decided
}

/// Whether the proxy may mint (or reuse) a leaf for a name: the CA is live and
/// the name is permitted. Split from [`tls_verdict`] because a leaf is minted
/// before the client's answer is known.
pub fn may_issue_leaf(ca_live: bool, now: u64, not_after: u64, name_permitted: bool) -> bool {
    ca_live && now <= not_after && name_permitted
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each refusal fires on its own, in the model's order.
    #[test]
    fn each_refusal_fires_alone_and_in_order() {
        use TlsVerdict::*;
        assert_eq!(tls_verdict(true, 5, 10, true, true, true), Decided);
        assert_eq!(tls_verdict(false, 5, 10, true, true, true), RefusedExpired);
        assert_eq!(tls_verdict(true, 11, 10, true, true, true), RefusedExpired);
        assert_eq!(
            tls_verdict(true, 10, 10, true, true, true),
            Decided,
            "the deadline itself is still live"
        );
        assert_eq!(
            tls_verdict(true, 5, 10, false, true, true),
            RefusedNameNotPermitted
        );
        assert_eq!(
            tls_verdict(true, 5, 10, true, false, true),
            RefusedClientRejected
        );
        assert_eq!(tls_verdict(true, 5, 10, true, true, false), RefusedFronting);
        // Expiry is reported before the name: a late handshake reveals nothing.
        assert_eq!(
            tls_verdict(true, 11, 10, false, false, false),
            RefusedExpired
        );
    }

    #[test]
    fn a_leaf_needs_a_live_ca_and_a_permitted_name() {
        assert!(may_issue_leaf(true, 5, 10, true));
        assert!(!may_issue_leaf(false, 5, 10, true));
        assert!(!may_issue_leaf(true, 11, 10, true));
        assert!(!may_issue_leaf(true, 5, 10, false));
    }
}
