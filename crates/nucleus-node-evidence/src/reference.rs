//! Reference values: what a node is expected to have booted and run.
//!
//! Field naming follows CoRIM (draft-ietf-rats-corim) where a name exists —
//! `tag-id`, `reference-values` — without its CBOR encoding. Every check is
//! an explicit [`Expect`]: a manifest says either what is required or, in
//! words, why something is not checked. There is no `Option` whose `None`
//! means "anything goes" (ADR 0007 B-2), and an appraisal reports every
//! `not_checked` item beside its verdict so an `Attested` result says what it
//! did not look at.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// The manifest's profile string.
pub const REFERENCE_PROFILE: &str = "nucleus-node-reference/v1";

/// A check that is either required or explicitly not made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expect<T> {
    /// The check is made against this reference.
    Required(T),
    /// The check is not made, and this says why.
    NotChecked(String),
}

/// A set of digests that may appear, and the subset that must.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestSet {
    /// Every observed digest must be one of these (SHA-256, lowercase hex).
    pub allowed: BTreeSet<String>,
    /// Each of these must be observed.
    pub required: BTreeSet<String>,
}

/// The kernel command line rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CmdlineRule {
    /// The measured command line equals this string.
    Exact(String),
    /// Each of these whitespace-separated parameters appears in it. It does
    /// NOT notice a parameter that was ADDED (measured live: an appended
    /// `nucleus.perturbed=1` satisfied it); prefer [`Self::ExactParams`].
    RequiredParams(BTreeSet<String>),
    /// The measured words are exactly this set: nothing missing, nothing
    /// added, in any order. GRUB measures the image path as the first word
    /// (`/vmlinuz-...`), where `/proc/cmdline` shows `BOOT_IMAGE=/vmlinuz-...`.
    ExactParams(BTreeSet<String>),
}

/// Which IMA measurements a manifest governs.
///
/// The scope is the manifest's, never the evidence's: the relying party
/// chose the manifest (a release's is Sigstore-signed), and nothing in the
/// evidence widens or sets it (ADR 0007 C-1). A measurement outside the scope
/// is neither allowed nor divergent: the appraisal lists it as not in scope
/// beside its verdict, so it is counted and named, never silently dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImaScope {
    /// Every measured file is appraised: a file the allowlist does not name is
    /// a divergence. The strictest scope, and the meaning of a manifest
    /// written before scopes existed.
    AllMeasured,
    /// Only files under these directories are appraised. Each is absolute,
    /// with no trailing `/` and no empty, `.` or `..` component. A measured
    /// path is in scope when it is a prefix followed by `/` and a non-empty
    /// rest. A release declares the directory its binaries are installed in,
    /// because it vouches for nothing else the host's IMA policy measures (a
    /// Secure Boot policy adds every kernel module the host loads).
    PathPrefixes(BTreeSet<String>),
}

impl ImaScope {
    /// The scope of a manifest that names none: the strictest.
    fn all_measured() -> Self {
        Self::AllMeasured
    }

    /// Whether a measured path is governed by this scope.
    pub fn contains(&self, path: &str) -> bool {
        match self {
            Self::AllMeasured => true,
            Self::PathPrefixes(prefixes) => prefixes.iter().any(|p| {
                path.strip_prefix(p.as_str())
                    .and_then(|rest| rest.strip_prefix('/'))
                    .is_some_and(|name| !name.is_empty())
            }),
        }
    }

    /// Why this scope is not well formed, if it is not.
    fn malformed(&self) -> Option<String> {
        let Self::PathPrefixes(prefixes) = self else {
            return None;
        };
        if prefixes.is_empty() {
            return Some("the IMA scope names no path prefix, so it governs nothing".into());
        }
        prefixes.iter().find_map(|p| {
            let well_formed = p
                .strip_prefix('/')
                .is_some_and(|rest| rest.split('/').all(|c| !matches!(c, "" | "." | "..")));
            (!well_formed).then(|| {
                format!(
                    "IMA scope prefix {p:?} is not an absolute directory without a trailing '/' \
                     or an empty, '.' or '..' component"
                )
            })
        })
    }
}

/// IMA reference values: the node's binaries by install path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImaReference {
    /// Which measurements this reference governs. Omitted, it is
    /// [`ImaScope::AllMeasured`]: the strictest scope, so a manifest published
    /// before scopes existed keeps its meaning, and an omission never narrows
    /// what is appraised.
    #[serde(default = "ImaScope::all_measured")]
    pub scope: ImaScope,
    /// Path → allowed SHA-256 file digests (hex). Every measured file in
    /// [`Self::scope`] must be here with one of its digests.
    pub allowlist: BTreeMap<String, BTreeSet<String>>,
    /// Paths that must have been measured (e.g. the node binary itself).
    pub required: BTreeSet<String>,
}

impl ImaReference {
    /// Why this reference cannot be applied as written, if it cannot: a
    /// malformed scope, or an allowlisted or required path outside it (a
    /// required path out of scope could never be satisfied; an allowlisted
    /// one would never be consulted). Appraisal reports this as not
    /// evaluable, never as a pass (ADR 0007 A-2); the manifest generators
    /// refuse to write it.
    pub fn incoherence(&self) -> Option<String> {
        if let Some(why) = self.scope.malformed() {
            return Some(why);
        }
        self.allowlist
            .keys()
            .chain(&self.required)
            .find(|p| !self.scope.contains(p))
            .map(|p| format!("{p} is allowlisted or required but outside the declared IMA scope"))
    }
}

/// The reference values proper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceValues {
    /// Exact SHA-256 PCR values, by index. Empty pins none.
    pub pcrs: BTreeMap<u8, String>,
    /// Secure Boot must be in this state.
    pub secure_boot: Expect<bool>,
    /// EFI applications loaded (PCR 4, Authenticode digests).
    pub efi_applications: Expect<DigestSet>,
    /// Files the boot loader loaded (PCR 9, SHA-256 of contents) — the kernel
    /// image and initrd.
    pub boot_files: Expect<DigestSet>,
    /// The kernel command line (PCR 8), which carries a dm-verity root hash
    /// when the root filesystem is verity-protected.
    pub kernel_cmdline: Expect<CmdlineRule>,
    /// Userspace measurements (PCR 10).
    pub ima: Expect<ImaReference>,
}

/// A reference manifest: one `tag-id`, one set of reference values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceManifest {
    /// Must equal [`REFERENCE_PROFILE`].
    pub profile: String,
    /// Identifies this manifest (CoRIM `tag-id`), e.g. a release version.
    #[serde(rename = "tag-id")]
    pub tag_id: String,
    /// What is expected.
    #[serde(rename = "reference-values")]
    pub reference_values: ReferenceValues,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape_round_trips_and_refuses_unknown_keys() {
        let m = ReferenceManifest {
            profile: REFERENCE_PROFILE.into(),
            tag_id: "node-1.0.0".into(),
            reference_values: ReferenceValues {
                pcrs: BTreeMap::new(),
                secure_boot: Expect::Required(true),
                efi_applications: Expect::NotChecked("varies by image".into()),
                boot_files: Expect::NotChecked("x".into()),
                kernel_cmdline: Expect::Required(CmdlineRule::RequiredParams(
                    ["ima_hash=sha256".to_string()].into_iter().collect(),
                )),
                ima: Expect::NotChecked("x".into()),
            },
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""tag-id":"node-1.0.0""#));
        assert!(s.contains(r#""secure_boot":{"required":true}"#));
        assert_eq!(serde_json::from_str::<ReferenceManifest>(&s).unwrap(), m);
        let extra = s.replacen('{', r#"{"surprise":1,"#, 1);
        assert!(serde_json::from_str::<ReferenceManifest>(&extra).is_err());
        let missing = s.replace(r#""secure_boot":{"required":true},"#, "");
        assert!(
            serde_json::from_str::<ReferenceManifest>(&missing).is_err(),
            "an omitted check is a parse error, not an unchecked item"
        );
    }

    fn prefixes(ps: &[&str]) -> ImaScope {
        ImaScope::PathPrefixes(ps.iter().map(|p| p.to_string()).collect())
    }

    fn ima(scope: ImaScope, allowed: &[&str]) -> ImaReference {
        ImaReference {
            scope,
            allowlist: allowed
                .iter()
                .map(|p| (p.to_string(), BTreeSet::new()))
                .collect(),
            required: BTreeSet::new(),
        }
    }

    #[test]
    fn a_scope_prefix_matches_whole_components_only() {
        let s = prefixes(&["/usr/local/bin"]);
        assert!(s.contains("/usr/local/bin/nucleus-node"));
        assert!(s.contains("/usr/local/bin/sub/dir"));
        assert!(
            !s.contains("/usr/local/bin"),
            "the directory is not a file in it"
        );
        assert!(!s.contains("/usr/local/bin/"));
        assert!(!s.contains("/usr/local/binx/implant"));
        assert!(!s.contains("/usr/lib/modules/7.0.0/kernel/x.ko"));
        assert!(!s.contains("usr/local/bin/relative"));
        // A non-canonical spelling under the prefix is IN scope, so it is
        // appraised and, unlisted, contests: the conservative direction.
        assert!(s.contains("/usr/local/bin/../../../tmp/implant"));
        assert!(ImaScope::AllMeasured.contains("/anything"));
    }

    #[test]
    fn a_malformed_scope_or_an_allowlist_outside_it_is_incoherent() {
        let bad: [&[&str]; 7] = [
            &[],
            &["/"],
            &["/usr/local/bin/"],
            &["usr/bin"],
            &["/a//b"],
            &["/a/../b"],
            &["/a/."],
        ];
        for b in bad {
            assert!(
                ima(prefixes(b), &[]).incoherence().is_some(),
                "{b:?} must be refused"
            );
        }
        let ok = ima(
            prefixes(&["/usr/local/bin"]),
            &["/usr/local/bin/nucleus-node"],
        );
        assert_eq!(ok.incoherence(), None);
        let outside = ima(prefixes(&["/usr/local/bin"]), &["/opt/nucleus-node"]);
        assert!(outside.incoherence().unwrap().contains("/opt/nucleus-node"));
        let mut required_outside = ok.clone();
        required_outside.required.insert("/opt/nucleus-node".into());
        assert!(required_outside.incoherence().is_some());
        assert_eq!(ima(ImaScope::AllMeasured, &["/x"]).incoherence(), None);
    }

    #[test]
    fn an_omitted_scope_is_all_measured_and_a_written_one_round_trips() {
        let legacy = r#"{"allowlist":{"/usr/local/bin/nucleus-node":["aa"]},"required":[]}"#;
        let r: ImaReference = serde_json::from_str(legacy).unwrap();
        assert_eq!(r.scope, ImaScope::AllMeasured);
        let scoped = ima(prefixes(&["/usr/local/bin"]), &[]);
        let json = serde_json::to_string(&scoped).unwrap();
        assert!(
            json.contains(r#""scope":{"path_prefixes":["/usr/local/bin"]}"#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<ImaReference>(&json).unwrap(), scoped);
        let all = serde_json::to_string(&ima(ImaScope::AllMeasured, &[])).unwrap();
        assert!(all.contains(r#""scope":"all_measured""#), "{all}");
    }
}
