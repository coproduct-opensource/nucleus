//! The version a nucleus binary reports about itself (#3208).
//!
//! `nucleus --version` and `nucleus-node --version` printed the workspace's Cargo
//! version, `1.0.0`, on every release since v2.0.0: releases are cut from tags and
//! the workspace version was never moved with them. Bumping it is not the fix —
//! it cascades into every crate, the wasm-embedded verifier crates included — so
//! the binaries report what their build actually knew instead:
//!
//! 1. **The release tag.** The release workflow builds on a tag push, and the
//!    runner exports `GITHUB_REF_TYPE=tag` and `GITHUB_REF_NAME=v2.7.0` to every
//!    step (and `Cross.toml` passes both into the musl `cross` builds). Only a
//!    full `vMAJOR.MINOR.PATCH` tag is reported; a branch build's ref name, the
//!    floating major tag `v2`, or any other tag is not.
//! 2. **Otherwise** the Cargo version with `+dev`, which says outright that this
//!    is not a release build rather than passing for one.
//!
//! There is deliberately no `git describe` fallback: it needs a build script per
//! binary crate, and a new build target moves the generated gatehouse test-shard
//! layout (`cargo xtask test-shards --check`), which is not this change's to edit.
//!
//! One decider for both binaries: [`reported_version!`](crate::reported_version)
//! expands in the calling crate, so the build-time inputs are that crate's.

use std::fmt;

/// What a build knew about its own version, and where that came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportedVersion {
    /// Built by the release workflow for a version tag (the `v` dropped).
    ReleaseTag(String),
    /// Not a release build: the Cargo version, reported with a `+dev` marker.
    Untagged(String),
}

impl fmt::Display for ReportedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReleaseTag(v) => f.write_str(v),
            Self::Untagged(cargo) => write!(f, "{cargo}+dev"),
        }
    }
}

/// The build-time inputs, each `None` when the build did not have it.
#[derive(Debug, Clone, Copy)]
pub struct BuildInputs<'a> {
    /// `CARGO_PKG_VERSION`.
    pub cargo_version: &'a str,
    /// `GITHUB_REF_TYPE`: `tag` on a tag push, `branch` otherwise.
    pub ref_type: Option<&'a str>,
    /// `GITHUB_REF_NAME`: the tag or branch name.
    pub ref_name: Option<&'a str>,
}

/// Decide what to report. See the module docs.
pub fn decide(inputs: BuildInputs<'_>) -> ReportedVersion {
    if inputs.ref_type == Some("tag")
        && let Some(v) = inputs.ref_name.and_then(version_from_tag)
    {
        return ReportedVersion::ReleaseTag(v.to_string());
    }
    ReportedVersion::Untagged(inputs.cargo_version.to_string())
}

/// `v2.7.0` → `2.7.0`, and `nucleus-node-v2.7.0` likewise (the release workflow
/// strips both prefixes when it names its tarballs). The rest must be a full
/// `MAJOR.MINOR.PATCH`, optionally followed by a `-`/`+` suffix of version
/// characters; anything else is `None`.
fn version_from_tag(tag: &str) -> Option<&str> {
    let v = tag
        .strip_prefix("nucleus-node-v")
        .or_else(|| tag.strip_prefix('v'))?;
    let (core, suffix) = v.split_at(v.find(['-', '+']).unwrap_or(v.len()));
    let numbers: Vec<&str> = core.split('.').collect();
    let three_numbers = numbers.len() == 3
        && numbers
            .iter()
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    let suffix_chars = suffix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'));
    (three_numbers && suffix_chars).then_some(v)
}

/// The version string for the calling binary, decided from ITS build inputs.
///
/// A macro so that `option_env!` is evaluated when the binary's own crate is
/// compiled: the release tag is in the environment of that compilation.
#[macro_export]
macro_rules! reported_version {
    () => {
        $crate::release_version::decide($crate::release_version::BuildInputs {
            cargo_version: env!("CARGO_PKG_VERSION"),
            ref_type: option_env!("GITHUB_REF_TYPE"),
            ref_name: option_env!("GITHUB_REF_NAME"),
        })
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs<'a>(ref_type: Option<&'a str>, ref_name: Option<&'a str>) -> BuildInputs<'a> {
        BuildInputs {
            cargo_version: "1.0.0",
            ref_type,
            ref_name,
        }
    }

    #[test]
    fn a_release_tag_build_reports_the_tag() {
        let v = decide(inputs(Some("tag"), Some("v2.7.0")));
        assert_eq!(v, ReportedVersion::ReleaseTag("2.7.0".into()));
        assert_eq!(v.to_string(), "2.7.0");
        assert_eq!(
            decide(inputs(Some("tag"), Some("v2.8.0-rc.1"))).to_string(),
            "2.8.0-rc.1"
        );
        assert_eq!(
            decide(inputs(Some("tag"), Some("nucleus-node-v2.7.0"))).to_string(),
            "2.7.0"
        );
    }

    /// A branch build carries `GITHUB_REF_NAME` too — a branch name is never a
    /// version, even one that looks like one.
    #[test]
    fn a_branch_build_never_reports_its_ref_name() {
        assert_eq!(
            decide(inputs(Some("branch"), Some("v2.7.0"))),
            ReportedVersion::Untagged("1.0.0".into())
        );
        assert_eq!(
            decide(inputs(None, Some("v2.7.0"))),
            ReportedVersion::Untagged("1.0.0".into())
        );
    }

    /// Including the floating major tag `v2`, which the release workflow moves
    /// onto every release commit.
    #[test]
    fn a_tag_that_is_not_a_version_is_not_reported() {
        let not_versions = [
            "latest",
            "v",
            "vnext",
            "v2",
            "v2.7",
            "v2.7.0.1",
            "v2..0",
            "v2.7.x",
            "v2.7.0 ",
            "v2.7.0/../x",
            "",
        ];
        for tag in not_versions {
            assert_eq!(
                decide(inputs(Some("tag"), Some(tag))),
                ReportedVersion::Untagged("1.0.0".into()),
                "{tag:?}"
            );
        }
    }

    /// Not a release build: the Cargo version, marked, never bare.
    #[test]
    fn without_a_release_tag_the_cargo_version_is_marked_dev() {
        let v = decide(inputs(None, None));
        assert_eq!(v.to_string(), "1.0.0+dev");
    }
}
