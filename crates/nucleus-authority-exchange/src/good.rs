//! What a round allocates, named by the operator rather than by this crate.
//!
//! # Why this is not `PermissionDimension`
//!
//! The exchange was written against `nucleus_permission_market::PermissionDimension`
//! — filesystem, command exec, network egress, approval — because the first
//! scarce thing it rationed was authority inside one pod. That made the
//! mechanism unusable for the scarce thing that actually contends in a build
//! flow: a runner slot, a merge-queue attempt, a cache write. The kernel,
//! the Clarke pivot and the receipt do not care what the good IS; only the
//! type did.
//!
//! So a round allocates a [`ScarceGood`]: an operator-chosen label. A
//! `PermissionDimension` converts into one, so the in-pod authority exchange
//! is unchanged and every existing receipt keeps its proposal id.
//!
//! # Where the boundary sits
//!
//! This crate is the MECHANISM and stays public (ADR 0009). The thing that
//! OPERATES a market for CI capacity — durable queues, attempt leases,
//! retries, cache admission — belongs to Gatehouse per this repository's own
//! ownership rule, and always did. What was missing was a public mechanism it
//! could clear with, rather than one hard-wired to a pod's permission lattice.
//!
//! # The label is a declared input
//!
//! It becomes the clearing receipt's `proposal_id`, so it is hashed into the
//! receipt's content and a third party recomputing the round sees which good
//! was sold. That is why the constructor validates rather than trusting: a
//! label with a `/` in it would collide with the `authority-slot/<label>`
//! scheme, and an unbounded one would let a bidder inflate every receipt it
//! appears in.

use std::fmt;

/// The largest label that may name a good. Generous for a human-readable name,
/// small enough that it cannot inflate a receipt.
const MAX_LABEL: usize = 64;

/// A scarce good one round allocates identical units of.
///
/// The field is private and the constructor validates: see the module docs on
/// why the label is a declared, hashed input rather than free text.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScarceGood(String);

/// Why a label cannot name a good.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GoodError {
    /// The empty label names nothing, and would make two receipts for
    /// different goods look alike.
    #[error("a scarce good's label may not be empty")]
    Empty,
    /// Longer than [`MAX_LABEL`].
    #[error("a scarce good's label may be at most {MAX_LABEL} bytes, got {got}")]
    TooLong { got: usize },
    /// `/` is the separator in the `authority-slot/<label>` proposal id, and
    /// whitespace or control characters would make a receipt's declared input
    /// unreadable in the logs that carry it.
    #[error("a scarce good's label may not contain {ch:?}")]
    BadChar { ch: char },
}

impl ScarceGood {
    /// Name a good, or say why the label cannot.
    ///
    /// Permitted: ASCII alphanumerics, `_`, `-`, `.`. That is enough for
    /// `network_egress`, `ci-runner-slot` and `cache.write`, and excludes the
    /// separator and anything that would not survive a log line intact.
    pub fn new(label: impl Into<String>) -> Result<Self, GoodError> {
        let label = label.into();
        if label.is_empty() {
            return Err(GoodError::Empty);
        }
        if label.len() > MAX_LABEL {
            return Err(GoodError::TooLong { got: label.len() });
        }
        if let Some(ch) = label
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
        {
            return Err(GoodError::BadChar { ch });
        }
        Ok(Self(label))
    }

    /// The label, as it appears in a receipt's proposal id.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScarceGood {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<nucleus_permission_market::PermissionDimension> for ScarceGood {
    /// Every permission dimension is a good this exchange can ration, and its
    /// `label()` is already the spelling receipts carry — so an in-pod round
    /// clears exactly as it did before this type existed.
    fn from(dimension: nucleus_permission_market::PermissionDimension) -> Self {
        // `label()` returns one of four `&'static str`s, all of which satisfy
        // `new`. Infallible in practice; the fallback keeps the conversion
        // total rather than panicking if a fifth dimension is added with a
        // spelling this type would reject — the gate on that is the test
        // below, which walks `PermissionDimension::ALL`.
        Self::new(dimension.label()).unwrap_or_else(|_| Self("unnameable-dimension".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_permission_market::PermissionDimension;

    /// EVERY permission dimension must convert to a good whose label is its
    /// own, or an in-pod round would clear under a different name than its
    /// receipts have always carried. The fallback in `from` is unreachable
    /// while this passes, and this is what makes adding a fifth dimension with
    /// a bad spelling a test failure rather than a silent rename.
    #[test]
    fn every_permission_dimension_names_a_good_by_its_own_label() {
        for d in PermissionDimension::ALL {
            let good = ScarceGood::from(*d);
            assert_eq!(
                good.label(),
                d.label(),
                "{d:?} must keep the spelling its receipts carry"
            );
            assert_ne!(good.label(), "unnameable-dimension");
        }
    }

    #[test]
    fn a_ci_capacity_label_is_nameable() {
        for label in ["ci-runner-slot", "merge_queue_attempt", "cache.write"] {
            assert_eq!(
                ScarceGood::new(label).expect("nameable").label(),
                label,
                "an operator's own scarce good must be expressible"
            );
        }
    }

    /// The separator, and the two shapes that would corrupt a receipt's
    /// declared input.
    #[test]
    fn a_label_that_would_corrupt_a_receipt_is_refused() {
        assert_eq!(ScarceGood::new(""), Err(GoodError::Empty));
        assert_eq!(
            ScarceGood::new("authority-slot/network_egress"),
            Err(GoodError::BadChar { ch: '/' }),
            "the slot separator must not appear inside a label"
        );
        assert_eq!(
            ScarceGood::new("runner slot"),
            Err(GoodError::BadChar { ch: ' ' })
        );
        assert_eq!(
            ScarceGood::new("a\nb"),
            Err(GoodError::BadChar { ch: '\n' }),
            "a newline would split the log line a receipt travels on"
        );
        let long = "x".repeat(MAX_LABEL + 1);
        assert_eq!(
            ScarceGood::new(long.clone()),
            Err(GoodError::TooLong { got: long.len() })
        );
        // The boundary itself is allowed, so the limit is the stated one.
        assert!(ScarceGood::new("x".repeat(MAX_LABEL)).is_ok());
    }

    /// Two goods with the same label are the same good — the scheduler keys
    /// open rounds by this, so `Hash`/`Eq` deciding otherwise would open two
    /// rounds for one contended resource and price neither correctly.
    #[test]
    fn a_good_is_its_label() {
        use std::collections::HashMap;
        let a = ScarceGood::new("ci-runner-slot").unwrap();
        let b = ScarceGood::new("ci-runner-slot").unwrap();
        let c = ScarceGood::new("cache.write").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mut m: HashMap<ScarceGood, u8> = HashMap::new();
        m.insert(a, 1);
        m.insert(b, 2);
        assert_eq!(m.len(), 1, "one label, one open round");
        m.insert(c, 3);
        assert_eq!(m.len(), 2);
    }
}
