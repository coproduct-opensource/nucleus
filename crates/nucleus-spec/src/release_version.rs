//! The version a nucleus binary reports about itself (#3208).
//!
//! `nucleus --version` and `nucleus-node --version` printed the workspace's Cargo
//! version, `1.0.0`, on every release since v2.0.0: releases are cut from tags and
//! the workspace version was never moved with them. Bumping it is not the fix —
//! it cascades into every crate, the wasm-embedded verifier crates included — so
//! the binaries report what their build actually knew instead, in this order:
//!
//! 1. **The release tag.** The release workflow builds on a tag push, and the
//!    runner exports `GITHUB_REF_TYPE=tag` and `GITHUB_REF_NAME=v2.7.0` to every
//!    step. A tag that does not read as a version is ignored, not reported.
//! 2. **`git describe`**, when the build had a checkout and a git to ask (each
//!    binary's `build.rs` hands it over as `NUCLEUS_GIT_DESCRIBE`). This is
//!    `2.7.0` only when HEAD is exactly on that tag and the tree is clean;
//!    otherwise it carries the distance and commit (`2.7.0-14-gabc1234`) and
//!    `-dirty`, so it never claims a tag the build was not on.
//! 3. **Neither**: the Cargo version with `+dev`, which says outright that this
//!    is not a release build rather than passing for one.
//!
//! One decider for both binaries: [`reported_version!`](crate::reported_version)
//! expands in the calling crate, so the build-time inputs are that crate's.

use std::fmt;

/// What a build knew about its own version, and where that came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportedVersion {
    /// Built by the release workflow for a version tag (the `v` dropped).
    ReleaseTag(String),
    /// Built from a git checkout: `git describe` output (the `v` dropped).
    Describe(String),
    /// Neither: the Cargo version, reported with a `+dev` marker.
    Untagged(String),
}

impl fmt::Display for ReportedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReleaseTag(v) | Self::Describe(v) => f.write_str(v),
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
    /// `git describe --tags --match 'v[0-9]*.[0-9]*.[0-9]*' --dirty`, from `build.rs`.
    pub git_describe: Option<&'a str>,
}

/// Decide what to report. See the module docs for the order.
pub fn decide(inputs: BuildInputs<'_>) -> ReportedVersion {
    if inputs.ref_type == Some("tag")
        && let Some(v) = inputs.ref_name.and_then(version_from_tag)
    {
        return ReportedVersion::ReleaseTag(v.to_string());
    }
    if let Some(v) = inputs
        .git_describe
        .map(str::trim)
        .and_then(version_from_tag)
    {
        return ReportedVersion::Describe(v.to_string());
    }
    ReportedVersion::Untagged(inputs.cargo_version.to_string())
}

/// `v2.7.0` → `2.7.0`, and `nucleus-node-v2.7.0` likewise (the release workflow
/// strips both prefixes when it names its tarballs). The rest must be a full
/// `MAJOR.MINOR.PATCH`, optionally followed by a `-`/`+` suffix of version
/// characters; anything else is `None`. That refuses a branch-like tag name,
/// and the floating major tag `v2` the release workflow moves to each release:
/// `git describe` finds it as readily as `v2.7.0` and would report `2-82-g…`.
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
/// compiled: the release tag is in the environment of that compilation, and the
/// `NUCLEUS_GIT_DESCRIBE` its `build.rs` set exists only there.
#[macro_export]
macro_rules! reported_version {
    () => {
        $crate::release_version::decide($crate::release_version::BuildInputs {
            cargo_version: env!("CARGO_PKG_VERSION"),
            ref_type: option_env!("GITHUB_REF_TYPE"),
            ref_name: option_env!("GITHUB_REF_NAME"),
            git_describe: option_env!("NUCLEUS_GIT_DESCRIBE"),
        })
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs<'a>(
        ref_type: Option<&'a str>,
        ref_name: Option<&'a str>,
        git_describe: Option<&'a str>,
    ) -> BuildInputs<'a> {
        BuildInputs {
            cargo_version: "1.0.0",
            ref_type,
            ref_name,
            git_describe,
        }
    }

    #[test]
    fn a_release_tag_build_reports_the_tag() {
        let v = decide(inputs(Some("tag"), Some("v2.7.0"), None));
        assert_eq!(v, ReportedVersion::ReleaseTag("2.7.0".into()));
        assert_eq!(v.to_string(), "2.7.0");
        assert_eq!(
            decide(inputs(Some("tag"), Some("v2.8.0-rc.1"), None)).to_string(),
            "2.8.0-rc.1"
        );
        assert_eq!(
            decide(inputs(Some("tag"), Some("nucleus-node-v2.7.0"), None)).to_string(),
            "2.7.0"
        );
    }

    /// The tag outranks a describe: the release workflow's checkout is shallow
    /// and may not describe at all, and when it does, the tag is the fact.
    #[test]
    fn the_release_tag_outranks_git_describe() {
        let v = decide(inputs(
            Some("tag"),
            Some("v2.7.0"),
            Some("v2.6.0-3-gabc1234"),
        ));
        assert_eq!(v, ReportedVersion::ReleaseTag("2.7.0".into()));
    }

    /// A branch build carries `GITHUB_REF_NAME` too — a branch name is never a
    /// version, even one that looks like one.
    #[test]
    fn a_branch_build_never_reports_its_ref_name() {
        assert_eq!(
            decide(inputs(Some("branch"), Some("v2.7.0"), None)),
            ReportedVersion::Untagged("1.0.0".into())
        );
        assert_eq!(
            decide(inputs(None, Some("v2.7.0"), None)),
            ReportedVersion::Untagged("1.0.0".into())
        );
    }

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
                decide(inputs(Some("tag"), Some(tag), None)),
                ReportedVersion::Untagged("1.0.0".into()),
                "{tag:?}"
            );
        }
    }

    /// Measured on a real checkout: without a full-version `--match`, `git
    /// describe` finds the floating major tag `v2` on the release commit and
    /// says `v2-82-g24e6c937`. That is not a version and must not be reported.
    #[test]
    fn a_describe_off_the_floating_major_tag_is_not_a_version() {
        assert_eq!(
            decide(inputs(None, None, Some("v2-82-g24e6c937"))),
            ReportedVersion::Untagged("1.0.0".into())
        );
    }

    #[test]
    fn git_describe_keeps_its_distance_and_dirt() {
        assert_eq!(
            decide(inputs(None, None, Some("v2.7.0\n"))).to_string(),
            "2.7.0"
        );
        assert_eq!(
            decide(inputs(None, None, Some("v2.7.0-14-gabc1234"))).to_string(),
            "2.7.0-14-gabc1234"
        );
        assert_eq!(
            decide(inputs(None, None, Some("v2.7.0-dirty"))).to_string(),
            "2.7.0-dirty"
        );
        assert!(matches!(
            decide(inputs(None, None, Some("v2.7.0-14-gabc1234-dirty"))),
            ReportedVersion::Describe(_)
        ));
    }

    /// No tag and no describe: the Cargo version, marked, never bare.
    #[test]
    fn with_neither_the_cargo_version_is_marked_dev() {
        let v = decide(inputs(None, None, None));
        assert_eq!(v.to_string(), "1.0.0+dev");
        assert_eq!(
            decide(inputs(None, None, Some("abc1234"))).to_string(),
            "1.0.0+dev",
            "a describe with no version tag behind it (`--always`) is not a version"
        );
    }
}
