//! Whether `setup` may replace a binary already at its destination (#2396).
//!
//! # Why this exists
//!
//! `setup` installed `nucleus` and `nucleus-node` by renaming over whatever
//! was at `/usr/local/bin`, with no comparison and no output. An operator who
//! had just installed their own build ran `setup` and got the release's
//! binaries back, silently. The next request failed as an authentication error
//! because the two ends spoke different protocol versions, and nothing pointed
//! at the swap.
//!
//! Now a binary is staged beside its destination first, both are fingerprinted
//! on the host, and [`decide`] chooses: install where there is nothing, skip
//! where they are identical, and refuse — naming both — where they differ,
//! unless the operator passed `--replace-binaries`.

/// What a binary reports about itself: its digest, and its `--version` if it
/// answers one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryFingerprint {
    /// SHA-256 of the file, lowercase hex. The comparison is on this alone:
    /// two builds of one version differ, and that difference is the point.
    pub sha256: String,
    /// What `--version` said. Only for the message.
    pub version: ReportedVersion,
}

/// A binary's own account of its version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportedVersion {
    /// The first line of `--version`.
    Reported(String),
    /// It did not answer `--version` (an older `nucleus-node` has no such flag).
    Unreported,
}

/// What is at the destination now.
///
/// Three answers (ADR 0007 A-1): "nothing is there" may be installed over;
/// "could not tell what is there" may not be read as either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstalledBinary {
    /// Nothing at the path.
    Absent,
    /// A file, fingerprinted.
    Present(BinaryFingerprint),
    /// Something is there, or might be, and it could not be fingerprinted.
    Unreadable {
        /// Why.
        reason: String,
    },
}

/// Whether the operator asked for differing binaries to be replaced.
///
/// No `Default` (ADR 0007 B-1): the CLI flag is the only constructor that
/// matters, and it states which one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceBinaries {
    /// Refuse to replace a binary that differs from the one being installed.
    Refuse,
    /// `--replace-binaries`: replace it, and say so.
    Replace,
}

/// What to do with one staged binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryInstall {
    /// Nothing was there: install.
    Fresh,
    /// Byte-identical to what is there: leave it and discard the staged copy.
    Identical,
    /// Different, and the operator asked for it to be replaced.
    Replace {
        /// What is being replaced, for the message.
        previous: InstalledBinary,
    },
    /// Different, and nobody asked: install nothing.
    Refuse(BinaryClash),
}

/// A binary at the destination that differs from the one `setup` would put
/// there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryClash {
    /// The destination.
    pub path: String,
    /// What is there. Never [`InstalledBinary::Absent`]: [`decide`] installs
    /// over nothing.
    pub installed: InstalledBinary,
    /// What would replace it.
    pub incoming: BinaryFingerprint,
    /// Where the incoming one came from, e.g. "release v2.3.0".
    pub origin: String,
}

impl std::fmt::Display for BinaryClash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{} is not the binary setup would install there, so it was left alone:",
            self.path
        )?;
        writeln!(f, "  installed: {}", describe_installed(&self.installed))?;
        writeln!(
            f,
            "  incoming:  {} (from {})",
            describe(&self.incoming),
            self.origin
        )?;
        write!(
            f,
            "Replacing it silently is how a locally built binary gets swapped for a \
             different one, after which the CLI and the node can disagree about the \
             protocol and every request fails as an authentication error (#2396). \
             To replace it, re-run with --replace-binaries."
        )
    }
}

impl std::error::Error for BinaryClash {}

/// One line for a fingerprint: its version and a digest prefix.
pub fn describe(fp: &BinaryFingerprint) -> String {
    let version = match &fp.version {
        ReportedVersion::Reported(v) => v.as_str(),
        ReportedVersion::Unreported => "version not reported",
    };
    format!("{version}, sha256 {}", short(&fp.sha256))
}

/// One line for whatever is at the destination.
pub fn describe_installed(installed: &InstalledBinary) -> String {
    match installed {
        InstalledBinary::Absent => "nothing".to_string(),
        InstalledBinary::Present(fp) => describe(fp),
        InstalledBinary::Unreadable { reason } => format!("could not be read ({reason})"),
    }
}

fn short(sha256: &str) -> &str {
    sha256.get(..16).unwrap_or(sha256)
}

/// The decision, on fingerprints already taken. Pure: every arm is a test.
pub fn decide(
    path: &str,
    installed: InstalledBinary,
    incoming: BinaryFingerprint,
    origin: &str,
    policy: ReplaceBinaries,
) -> BinaryInstall {
    match installed {
        InstalledBinary::Absent => BinaryInstall::Fresh,
        InstalledBinary::Present(ref fp) if fp.sha256 == incoming.sha256 => {
            BinaryInstall::Identical
        }
        // Different, or unknown. Unknown is never "the same" (A-1).
        InstalledBinary::Present(_) | InstalledBinary::Unreadable { .. } => match policy {
            ReplaceBinaries::Replace => BinaryInstall::Replace {
                previous: installed,
            },
            ReplaceBinaries::Refuse => BinaryInstall::Refuse(BinaryClash {
                path: path.to_string(),
                installed,
                incoming,
                origin: origin.to_string(),
            }),
        },
    }
}

/// A fingerprint from the host's `sha256sum` line and `--version` output.
/// `None` when the digest line is not one, which the caller reports as
/// unreadable rather than guessing.
pub fn fingerprint_from(
    sha256sum_line: &str,
    version_output: Option<&str>,
) -> Option<BinaryFingerprint> {
    let sha256 = super::sha256sum_digest(sha256sum_line)?.to_ascii_lowercase();
    let version =
        match version_output.and_then(|out| out.lines().map(str::trim).find(|l| !l.is_empty())) {
            Some(line) => ReportedVersion::Reported(line.to_string()),
            None => ReportedVersion::Unreported,
        };
    Some(BinaryFingerprint { sha256, version })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "/usr/local/bin/nucleus-node";

    fn fp(sha: char, version: &str) -> BinaryFingerprint {
        BinaryFingerprint {
            sha256: sha.to_string().repeat(64),
            version: ReportedVersion::Reported(version.to_string()),
        }
    }

    #[test]
    fn nothing_installed_is_a_fresh_install() {
        for policy in [ReplaceBinaries::Refuse, ReplaceBinaries::Replace] {
            assert_eq!(
                decide(
                    PATH,
                    InstalledBinary::Absent,
                    fp('a', "x"),
                    "release v2.3.0",
                    policy
                ),
                BinaryInstall::Fresh
            );
        }
    }

    #[test]
    fn an_identical_binary_is_skipped() {
        for policy in [ReplaceBinaries::Refuse, ReplaceBinaries::Replace] {
            assert_eq!(
                decide(
                    PATH,
                    InstalledBinary::Present(fp('a', "nucleus-node 2.3.0")),
                    fp('a', "nucleus-node 2.3.0"),
                    "release v2.3.0",
                    policy
                ),
                BinaryInstall::Identical
            );
        }
    }

    /// The #2396 case: a local build at the destination, a release incoming,
    /// no flag. Refused, and the message names both.
    #[test]
    fn a_different_binary_is_refused_and_both_are_named() {
        let decision = decide(
            PATH,
            InstalledBinary::Present(fp('a', "nucleus-node 2.3.0-dev")),
            fp('b', "nucleus-node 2.2.0"),
            "release v2.2.0",
            ReplaceBinaries::Refuse,
        );
        let BinaryInstall::Refuse(clash) = decision else {
            panic!("a differing binary must be refused without --replace-binaries: {decision:?}")
        };
        let msg = clash.to_string();
        assert!(msg.contains(PATH), "{msg}");
        assert!(
            msg.contains("nucleus-node 2.3.0-dev, sha256 aaaaaaaaaaaaaaaa"),
            "{msg}"
        );
        assert!(
            msg.contains("nucleus-node 2.2.0, sha256 bbbbbbbbbbbbbbbb"),
            "{msg}"
        );
        assert!(msg.contains("release v2.2.0"), "{msg}");
        assert!(msg.contains("--replace-binaries"), "{msg}");
    }

    /// Same version string, different bytes: still different. The version is
    /// for the message; the digest decides.
    #[test]
    fn the_same_version_with_different_bytes_is_still_refused() {
        let decision = decide(
            PATH,
            InstalledBinary::Present(fp('a', "nucleus 2.3.0")),
            fp('b', "nucleus 2.3.0"),
            "this working tree",
            ReplaceBinaries::Refuse,
        );
        assert!(matches!(decision, BinaryInstall::Refuse(_)), "{decision:?}");
    }

    /// Could not look is never read as "identical" or "absent".
    #[test]
    fn an_unreadable_destination_is_refused() {
        let installed = InstalledBinary::Unreadable {
            reason: "sudo refused".into(),
        };
        let decision = decide(
            PATH,
            installed.clone(),
            fp('b', "x"),
            "release v2.3.0",
            ReplaceBinaries::Refuse,
        );
        let BinaryInstall::Refuse(clash) = decision else {
            panic!("an unreadable destination must be refused: {decision:?}")
        };
        assert!(
            clash
                .to_string()
                .contains("could not be read (sudo refused)")
        );
        assert_eq!(
            decide(
                PATH,
                installed.clone(),
                fp('b', "x"),
                "r",
                ReplaceBinaries::Replace
            ),
            BinaryInstall::Replace {
                previous: installed
            }
        );
    }

    #[test]
    fn the_flag_replaces_a_different_binary() {
        let previous = InstalledBinary::Present(fp('a', "nucleus 2.3.0-dev"));
        assert_eq!(
            decide(
                PATH,
                previous.clone(),
                fp('b', "nucleus 2.2.0"),
                "r",
                ReplaceBinaries::Replace
            ),
            BinaryInstall::Replace { previous }
        );
    }

    #[test]
    fn a_fingerprint_needs_a_real_digest_and_takes_the_first_version_line() {
        let line = format!("{}  /usr/local/bin/nucleus", "A".repeat(64));
        assert_eq!(
            fingerprint_from(&line, Some("\nnucleus 2.3.0\nmore\n")),
            Some(BinaryFingerprint {
                sha256: "a".repeat(64),
                version: ReportedVersion::Reported("nucleus 2.3.0".into()),
            })
        );
        assert_eq!(
            fingerprint_from(&line, None).map(|f| f.version),
            Some(ReportedVersion::Unreported)
        );
        assert_eq!(fingerprint_from("sha256sum: no such file", None), None);
    }
}
