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
    /// Each of these whitespace-separated parameters appears in it (for
    /// command lines that carry a per-machine value such as a partition id).
    RequiredParams(BTreeSet<String>),
}

/// IMA reference values: the node's binaries by install path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImaReference {
    /// Path → allowed SHA-256 file digests (hex). Every measured file must be
    /// here with one of its digests; the policy that produced the log is
    /// expected to be narrow (only the node's own files).
    pub allowlist: BTreeMap<String, BTreeSet<String>>,
    /// Paths that must have been measured (e.g. the node binary itself).
    pub required: BTreeSet<String>,
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
}
