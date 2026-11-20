//! Which hash a signed approval bundle for a pod must carry (#3395).
//!
//! An approval bundle names the manifest it approves by hash, and the guest's
//! tool-proxy refuses it unless that hash is the hash of the spec it runs. Two
//! rules exist, one per guest generation:
//!
//! - a guest carrying [`GuestCapability::CanonicalManifestApproval`] binds the
//!   spec's canonical v3 manifest hash ([`crate::PodSpec::manifest_hash`], the
//!   hash a v3 receipt carries), so an approval binds what the spec means, not
//!   how a YAML writer spelled it;
//! - an older guest binds the SHA-256 of the `pod.yaml` bytes the node wrote.
//!
//! The guest decides which one it accepts; nothing negotiates. A bundle bound
//! the other way is refused there, so the question for a minter is only which
//! guest the pod runs on. [`ApprovalBinding::for_guest_release`] answers it from
//! the same release table every other skew decision reads (G-1), and the older
//! rule is a named variant rather than a default: "this guest predates the
//! canonical binding" is said, not assumed.
//!
//! [`ApprovalBinding::LegacySpecBytes`] is deleted once no guest release the
//! node serves lacks the row.

use crate::tier2_artifacts::{self, GuestCapability, GuestSkew};

/// The rule a guest uses to bind an approval bundle to its spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalBinding {
    /// [`crate::PodSpec::manifest_hash`]: SHA-256 over
    /// [`crate::manifest_hash::MANIFEST_HASH_DOMAIN`] and the spec's RFC 8785
    /// JSON. Carried by a guest with
    /// [`GuestCapability::CanonicalManifestApproval`].
    CanonicalManifest,
    /// The SHA-256 of the spec file's bytes as the node wrote them. Only a guest
    /// that predates [`GuestCapability::CanonicalManifestApproval`] binds this.
    LegacySpecBytes,
}

impl ApprovalBinding {
    /// The capability that decides between the two rules.
    pub const CAPABILITY: GuestCapability = GuestCapability::CanonicalManifestApproval;

    /// The binding the guest of release `release` enforces.
    ///
    /// # Errors
    ///
    /// [`GuestSkew::Unorderable`] when `release` cannot be ordered: the caller
    /// could not look, which is neither answer (ADR 0007 A-1).
    pub fn for_guest_release(release: &str) -> Result<Self, GuestSkew> {
        Self::from_skew(tier2_artifacts::capability_skew(release, Self::CAPABILITY))
    }

    /// The binding a release's skew against [`Self::CAPABILITY`] implies.
    /// Separate so the "has the row" arm is testable before any published
    /// release carries it.
    fn from_skew(skew: Result<(), GuestSkew>) -> Result<Self, GuestSkew> {
        match skew {
            Ok(()) => Ok(Self::CanonicalManifest),
            Err(GuestSkew::Lacks { .. }) => Ok(Self::LegacySpecBytes),
            Err(unorderable @ GuestSkew::Unorderable { .. }) => Err(unorderable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier2_artifacts::{FirstShipped, GUEST_RELEASE};

    /// The pinned release predates the row, so a bundle for a pod on it must
    /// carry the spec-bytes hash, and the answer says so by name.
    #[test]
    fn a_guest_without_the_row_binds_the_spec_bytes_by_name() {
        assert_eq!(
            GuestCapability::CanonicalManifestApproval.first_shipped(),
            FirstShipped::NotYet
        );
        assert_eq!(
            ApprovalBinding::for_guest_release(GUEST_RELEASE),
            Ok(ApprovalBinding::LegacySpecBytes)
        );
        assert_eq!(
            ApprovalBinding::for_guest_release("v2.6.0"),
            Ok(ApprovalBinding::LegacySpecBytes)
        );
    }

    /// An unorderable release is "could not look", never either binding.
    #[test]
    fn an_unorderable_release_is_neither_binding() {
        for release in ["main", "", "2.7"] {
            assert_eq!(
                ApprovalBinding::for_guest_release(release),
                Err(GuestSkew::Unorderable {
                    release: release.to_string()
                }),
                "{release:?}"
            );
        }
    }

    /// A guest whose release carries the row binds the canonical hash. No
    /// published release does yet, so the arm is driven through the skew it
    /// would report.
    #[test]
    fn a_guest_with_the_row_binds_the_canonical_hash() {
        assert_eq!(
            ApprovalBinding::from_skew(Ok(())),
            Ok(ApprovalBinding::CanonicalManifest)
        );
        assert_eq!(
            ApprovalBinding::from_skew(Err(GuestSkew::Lacks {
                release: "2.7.0".to_string(),
                missing: vec![ApprovalBinding::CAPABILITY],
            })),
            Ok(ApprovalBinding::LegacySpecBytes)
        );
    }
}
