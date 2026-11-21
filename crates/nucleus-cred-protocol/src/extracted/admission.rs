//! Which credentialed upstreams a pod is admitted: [`admitted_by`],
//! [`clamp`] and [`admit_upstreams`], generic over the entry type.
//!
//! These are the production deciders. `CredentialedEgressSpec::admitted_by`
//! and `::clamp` (`nucleus-spec`) and `PodAuthority::admit_upstreams`
//! (`nucleus-node`) call them with the spec type, whose derived `PartialEq`
//! compares every field ("whole-struct equality"). Generic, so the decision is
//! one definition whatever the entry is (ADR 0007 F-4) and its extraction is a
//! statement about every equality, not about one struct's.
//!
//! `while` loops over indices, not iterator adaptors: see `super::classify`.
//! Emptiness is `len() == 0`: `Vec::is_empty` is an opaque axiom in the
//! extraction, `len` a definition.

#![expect(
    clippy::len_zero,
    reason = "Vec::is_empty is an opaque axiom in the Aeneas extraction; len is a definition"
)]

/// Whether some entry of `ceiling` equals `entry`, comparing as
/// `granted == entry`.
pub fn admitted_by<T: PartialEq>(entry: &T, ceiling: &[T]) -> bool {
    let mut found = false;
    let mut i: usize = 0;
    while !found && i < ceiling.len() {
        found = ceiling[i] == *entry;
        i += 1;
    }
    found
}

/// `requested` split into what `ceiling` grants and what it does not, each
/// in request order.
pub fn clamp<T: PartialEq + Clone>(requested: &[T], ceiling: &[T]) -> (Vec<T>, Vec<T>) {
    let mut kept: Vec<T> = Vec::new();
    let mut dropped: Vec<T> = Vec::new();
    let mut i: usize = 0;
    while i < requested.len() {
        if admitted_by(&requested[i], ceiling) {
            kept.push(requested[i].clone());
        } else {
            dropped.push(requested[i].clone());
        }
        i += 1;
    }
    (kept, dropped)
}

/// A pod's requested upstreams, admitted against the operator's registry
/// (none is an empty ceiling: nothing is granted) and, for a pod caller, its
/// parent's admitted set.
///
/// `Ok` is the request, unchanged, when every entry is granted. `Err` names an
/// entry that is not: the first the registry refused, else the first the
/// parent refused.
pub fn admit_upstreams<T: PartialEq + Clone>(
    registry: Option<&[T]>,
    requested: &[T],
    parent: Option<&[T]>,
) -> Result<Vec<T>, T> {
    let (kept, dropped) = match registry {
        Some(entries) => clamp(requested, entries),
        None => clamp(requested, &[]),
    };
    let (kept, beyond_parent) = match parent {
        Some(held) => clamp(&kept, held),
        None => (kept, Vec::new()),
    };
    if dropped.len() > 0 {
        Err(dropped[0].clone())
    } else if beyond_parent.len() > 0 {
        Err(beyond_parent[0].clone())
    } else {
        Ok(kept)
    }
}
