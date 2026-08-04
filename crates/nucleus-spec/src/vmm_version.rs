//! Which VMM builds nucleus is willing to run a microVM on.
//!
//! # Why this exists
//!
//! Nucleus's isolation claim is delegated: the guest is confined by Firecracker
//! and the jailer, not by anything nucleus proves. So a Firecracker build with a
//! known escape is a hole in nucleus's boundary even though every line of
//! nucleus is correct. That makes "which VMM is installed" a security-relevant
//! input, and it was previously unchecked — `setup` installed a pinned version
//! and `doctor` compared against it with `String::contains`, which is an
//! *equality* test. It flagged a newer, patched build exactly as loudly as an
//! older, vulnerable one, and nothing stopped a pod launching on either.
//!
//! # Why a floor alone is not enough
//!
//! The obvious design — "refuse anything below the fixed version" — is wrong
//! here, and [`KNOWN_VULNERABLE`] is why. CVE-2026-5747 affects
//! `>=1.13.0, <=1.14.3` **and 1.15.0**, patched in 1.14.4 and 1.15.1. A plain
//! `>= 1.14.4` floor accepts 1.15.0, which is vulnerable. Version ranges with
//! holes are normal in multi-branch release streams, so the check is a floor
//! **plus** an explicit denylist, and `a_plain_floor_would_wrongly_accept_1_15_0`
//! pins that distinction.
//!
//! # What this does not do
//!
//! It reads a version string the VMM reports about itself. A replaced or lying
//! binary defeats it entirely — this raises the cost of running a stale host, it
//! does not attest anything. Binding to a *measured* binary is the attestation
//! work, and is not done anywhere in nucleus yet.

use std::fmt;

/// A three-part version, ordered the obvious way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VmmVersion {
    /// Major component.
    pub major: u32,
    /// Minor component.
    pub minor: u32,
    /// Patch component.
    pub patch: u32,
}

impl VmmVersion {
    /// Construct a version.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for VmmVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The Firecracker release `nucleus setup` installs.
///
/// 1.16.1 (2026-07-02) is the first release carrying the CVE-2026-5747 fix on
/// the current branch, and is also the build the jailer argv in
/// `nucleus-node::firecracker_config` was validated against — before this the
/// pin was 1.14.1 while the argv comments cited testing against 1.16.1.
pub const PINNED: VmmVersion = VmmVersion::new(1, 16, 1);

/// [`PINNED`] as a string, for building release download URLs.
///
/// A separate literal because `Display` is not `const`. It cannot drift from
/// `PINNED` — `pinned_str_matches_pinned` compares them.
pub const PINNED_STR: &str = "1.16.1";

/// The oldest release nucleus will launch a microVM on.
///
/// 1.14.4 is the CVE-2026-5747 fix for the 1.14 branch. Anything older is
/// refused outright rather than warned about.
pub const FLOOR: VmmVersion = VmmVersion::new(1, 14, 4);

/// Releases at or above [`FLOOR`] that are nonetheless known-vulnerable.
///
/// 1.15.0 shipped from a branch that had not taken the CVE-2026-5747 fix; it is
/// numerically above the floor and must still be refused. 1.15.1 is fine.
pub const KNOWN_VULNERABLE: &[VmmVersion] = &[VmmVersion::new(1, 15, 0)];

/// Why a VMM build was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmmVerdict {
    /// At or above the floor and not denylisted.
    Acceptable,
    /// Older than [`FLOOR`].
    BelowFloor {
        /// What was found.
        found: VmmVersion,
        /// What is required.
        floor: VmmVersion,
    },
    /// Above the floor but explicitly known-vulnerable.
    KnownVulnerable {
        /// What was found.
        found: VmmVersion,
    },
    /// The version string could not be parsed.
    Unparseable {
        /// The raw text that was reported.
        raw: String,
    },
}

impl VmmVerdict {
    /// Whether a microVM may be launched on this build.
    pub fn is_acceptable(&self) -> bool {
        matches!(self, VmmVerdict::Acceptable)
    }
}

impl fmt::Display for VmmVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmmVerdict::Acceptable => write!(f, "acceptable"),
            VmmVerdict::BelowFloor { found, floor } => write!(
                f,
                "Firecracker {found} is below the required floor {floor} — it carries known \
                 escape-class advisories; upgrade to {PINNED} (nucleus setup)"
            ),
            VmmVerdict::KnownVulnerable { found } => write!(
                f,
                "Firecracker {found} is explicitly known-vulnerable despite being above the \
                 floor {FLOOR} — upgrade to {PINNED} (nucleus setup)"
            ),
            VmmVerdict::Unparseable { raw } => write!(
                f,
                "could not read a Firecracker version from {raw:?} — refusing rather than \
                 assuming it is safe"
            ),
        }
    }
}

/// Pull the first `X.Y.Z` out of arbitrary VMM version output.
///
/// `firecracker --version` prints things like `Firecracker v1.16.1` and has
/// varied across releases, so this scans for the first dotted triple rather than
/// pinning a format. Returns `None` when there is no triple to find — callers
/// must treat that as a refusal, never as a pass.
pub fn parse_version(raw: &str) -> Option<VmmVersion> {
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // A digit run that is preceded by a digit or dot is the tail of
        // something already rejected; skip to the end of this token.
        let start = i;
        let mut parts: Vec<u32> = Vec::new();
        let mut j = start;
        while parts.len() < 3 {
            let num_start = j;
            let mut value: u64 = 0;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                // Saturate rather than overflow on absurd input.
                value = value
                    .saturating_mul(10)
                    .saturating_add(u64::from(bytes[j] - b'0'));
                j += 1;
            }
            if j == num_start {
                break;
            }
            parts.push(u32::try_from(value).unwrap_or(u32::MAX));
            if parts.len() < 3 {
                if j < bytes.len() && bytes[j] == b'.' {
                    j += 1;
                } else {
                    break;
                }
            }
        }
        if parts.len() == 3 {
            return Some(VmmVersion::new(parts[0], parts[1], parts[2]));
        }
        i = j.max(start + 1);
    }
    None
}

/// Judge a raw `--version` string.
pub fn judge(raw: &str) -> VmmVerdict {
    let Some(found) = parse_version(raw) else {
        return VmmVerdict::Unparseable {
            raw: raw.trim().to_string(),
        };
    };
    judge_version(found)
}

/// Judge an already-parsed version.
pub fn judge_version(found: VmmVersion) -> VmmVerdict {
    if found < FLOOR {
        return VmmVerdict::BelowFloor {
            found,
            floor: FLOOR,
        };
    }
    if KNOWN_VULNERABLE.contains(&found) {
        return VmmVerdict::KnownVulnerable { found };
    }
    VmmVerdict::Acceptable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_shapes_firecracker_actually_prints() {
        assert_eq!(parse_version("Firecracker v1.16.1"), Some(PINNED));
        assert_eq!(parse_version("v1.14.4"), Some(VmmVersion::new(1, 14, 4)));
        assert_eq!(parse_version("1.15.0"), Some(VmmVersion::new(1, 15, 0)));
        assert_eq!(
            parse_version("Firecracker v1.16.1-dev\nbuild 123"),
            Some(PINNED)
        );
    }

    /// Unparseable output must refuse, not pass. A VMM that prints nothing
    /// recognisable is exactly the case where assuming safety is worst.
    #[test]
    fn unreadable_output_is_refused_not_assumed_safe() {
        assert_eq!(parse_version("no version here"), None);
        assert!(!judge("").is_acceptable());
        assert!(!judge("garbage").is_acceptable());
        assert!(matches!(judge("garbage"), VmmVerdict::Unparseable { .. }));
    }

    /// THE POINT OF THE DENYLIST. 1.15.0 is numerically above the 1.14.4 floor
    /// and is still vulnerable to CVE-2026-5747 — it shipped from a branch that
    /// had not taken the fix. A floor-only check accepts it.
    ///
    /// Delete `KNOWN_VULNERABLE` from `judge_version` and this test is the one
    /// that fails; the ordering tests below all still pass.
    #[test]
    fn a_plain_floor_would_wrongly_accept_1_15_0() {
        let v = VmmVersion::new(1, 15, 0);
        assert!(v > FLOOR, "1.15.0 really is above the floor");
        assert!(
            !judge_version(v).is_acceptable(),
            "1.15.0 is above the floor and still vulnerable; the floor alone is not enough"
        );
        // …and the patched sibling on the same branch is fine.
        assert!(judge_version(VmmVersion::new(1, 15, 1)).is_acceptable());
    }

    #[test]
    fn the_vulnerable_range_is_refused_and_the_fixes_are_not() {
        // CVE-2026-5747 affects >=1.13.0, <=1.14.3, and 1.15.0.
        for bad in [(1, 13, 0), (1, 14, 0), (1, 14, 1), (1, 14, 3), (1, 15, 0)] {
            let v = VmmVersion::new(bad.0, bad.1, bad.2);
            assert!(
                !judge_version(v).is_acceptable(),
                "{v} is in the CVE-2026-5747 range and must be refused"
            );
        }
        for good in [(1, 14, 4), (1, 15, 1), (1, 16, 1), (2, 0, 0)] {
            let v = VmmVersion::new(good.0, good.1, good.2);
            assert!(judge_version(v).is_acceptable(), "{v} should be accepted");
        }
    }

    /// The old pin, kept as a regression marker: 1.14.1 was shipped by `setup`
    /// and would now be refused.
    #[test]
    fn the_previous_pin_is_below_the_floor() {
        assert!(!judge_version(VmmVersion::new(1, 14, 1)).is_acceptable());
    }

    /// The download URL and the acceptance check must name the same release, or
    /// `setup` installs something `doctor` then rejects.
    #[test]
    fn pinned_str_matches_pinned() {
        assert_eq!(PINNED_STR, PINNED.to_string());
        assert_eq!(parse_version(PINNED_STR), Some(PINNED));
    }

    #[test]
    fn the_pin_satisfies_its_own_floor() {
        assert!(
            judge_version(PINNED).is_acceptable(),
            "the version we install must pass the check we enforce"
        );
    }

    #[test]
    fn refusals_name_the_version_and_the_remedy() {
        let msg = judge_version(VmmVersion::new(1, 14, 1)).to_string();
        assert!(msg.contains("1.14.1"), "must name what was found: {msg}");
        assert!(msg.contains("1.16.1"), "must name the remedy: {msg}");
    }
}
