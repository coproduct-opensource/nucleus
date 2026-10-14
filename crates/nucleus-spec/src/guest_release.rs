//! Which guest a node boots, as the NODE reports it (#3223).
//!
//! # Why the node says it
//!
//! `nucleus run --egress` and `--isolation-profile eval-cell` depend on
//! capabilities of the guest rootfs ([`GuestCapability`](crate::tier2_artifacts::GuestCapability)),
//! and the CLI used to judge them against a release it had no record of: the
//! pinned one by default, or whatever `--guest-release` said. Both were claims
//! about a file on another machine that nothing checked.
//!
//! The node has the file. `nucleus setup` installs the rootfs and, beside it,
//! a [`GuestReleaseRecord`] naming where it came from and the SHA-256 of the
//! bytes it installed. The node measures the rootfs at startup and reports
//! the record's origin only when the bytes are the ones the record names
//! ([`NodeGuestReport::Known`]); anything else is
//! [`NodeGuestReport::Unknown`] with the reason, never a default that reads as
//! known (ADR 0007 A-1).
//!
//! # What it does not establish
//!
//! The record is written by the installer, so "release 2.7.0" means "the bytes
//! `setup` installed when it installed release 2.7.0", not a property read off
//! the image. The digest binds the report to those bytes; it does not
//! re-derive the release from them. The report is advisory for the CLI's
//! preflight: the node's own boot-time checks still refuse a guest that lacks
//! a capability it requires, whatever was reported.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::tier2_artifacts::parse_release;

/// The record's file name, beside the rootfs in the artifacts directory
/// ([`HOST_ARTIFACTS_DIR`](crate::tier2_artifacts::HOST_ARTIFACTS_DIR)).
pub const GUEST_RELEASE_RECORD_FILE: &str = "rootfs.release.json";

/// The one schema identifier a [`GuestReleaseRecord`] carries.
pub const GUEST_RELEASE_RECORD_SCHEMA: &str = "nucleus.guest-release-record.v1";

/// How `--guest-release` spells a guest built from a working tree
/// (`nucleus setup --artifacts local`).
pub const LOCAL_BUILD: &str = "local";

/// Where a guest rootfs came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestOrigin {
    /// A published release's rootfs asset.
    Release {
        /// The release, as `setup` named it (no `v`).
        version: String,
    },
    /// A rootfs built from a working tree, which carries what that tree
    /// carries; no release table describes it.
    LocalBuild,
}

impl GuestOrigin {
    /// Read the `--guest-release` spelling: [`LOCAL_BUILD`], or a release.
    pub fn from_flag(raw: &str) -> Self {
        if raw == LOCAL_BUILD {
            Self::LocalBuild
        } else {
            Self::Release {
                version: raw.trim_start_matches('v').to_string(),
            }
        }
    }

    /// Whether two origins name the same guest. Releases compare by their
    /// ordered core when both parse (`v2.7.0` is `2.7.0`), and by spelling
    /// otherwise; a release is never a local build.
    pub fn same_guest(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::LocalBuild, Self::LocalBuild) => true,
            (Self::Release { version: a }, Self::Release { version: b }) => {
                match (parse_release(a), parse_release(b)) {
                    (Some(a), Some(b)) => a == b,
                    _ => a.trim_start_matches('v') == b.trim_start_matches('v'),
                }
            }
            (Self::LocalBuild, Self::Release { .. }) | (Self::Release { .. }, Self::LocalBuild) => {
                false
            }
        }
    }
}

impl fmt::Display for GuestOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Release { version } => {
                write!(f, "release v{}", version.trim_start_matches('v'))
            }
            Self::LocalBuild => write!(f, "a local build (`--guest-release {LOCAL_BUILD}`)"),
        }
    }
}

/// What `nucleus setup` writes beside the rootfs it installs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestReleaseRecord {
    /// Always [`GUEST_RELEASE_RECORD_SCHEMA`].
    schema: String,
    /// Where the rootfs came from.
    origin: GuestOrigin,
    /// Lowercase hex SHA-256 of the installed (decompressed) rootfs.
    rootfs_sha256: String,
}

/// Why a [`GuestReleaseRecord`] was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// Not JSON of the record's shape.
    Malformed(String),
    /// A schema this build does not read.
    Schema(String),
    /// The digest is not 64 lowercase hex characters.
    Digest(String),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "not a guest release record: {e}"),
            Self::Schema(s) => write!(
                f,
                "schema {s:?} is not {GUEST_RELEASE_RECORD_SCHEMA:?}, the one this build reads"
            ),
            Self::Digest(d) => write!(f, "rootfs_sha256 {d:?} is not a lowercase hex SHA-256"),
        }
    }
}

impl std::error::Error for RecordError {}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl GuestReleaseRecord {
    /// A record of the current schema.
    ///
    /// # Errors
    /// [`RecordError::Digest`] when `rootfs_sha256` is not lowercase hex SHA-256.
    pub fn new(origin: GuestOrigin, rootfs_sha256: &str) -> Result<Self, RecordError> {
        if !is_sha256_hex(rootfs_sha256) {
            return Err(RecordError::Digest(rootfs_sha256.to_string()));
        }
        Ok(Self {
            schema: GUEST_RELEASE_RECORD_SCHEMA.to_string(),
            origin,
            rootfs_sha256: rootfs_sha256.to_string(),
        })
    }

    /// Read a record, refusing an unknown schema or a malformed digest.
    ///
    /// # Errors
    /// The bytes are not a record this build accepts.
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        let record: Self =
            serde_json::from_slice(bytes).map_err(|e| RecordError::Malformed(e.to_string()))?;
        if record.schema != GUEST_RELEASE_RECORD_SCHEMA {
            return Err(RecordError::Schema(record.schema));
        }
        if !is_sha256_hex(&record.rootfs_sha256) {
            return Err(RecordError::Digest(record.rootfs_sha256));
        }
        Ok(record)
    }

    /// Where the rootfs came from.
    pub fn origin(&self) -> &GuestOrigin {
        &self.origin
    }

    /// The digest of the rootfs the record describes.
    pub fn rootfs_sha256(&self) -> &str {
        &self.rootfs_sha256
    }
}

/// What a node says about the guest rootfs it boots by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeGuestReport {
    /// The rootfs at `rootfs_path` is, byte for byte, the one its record names.
    Known {
        /// Where it came from, per the record.
        origin: GuestOrigin,
        /// The file the node measured.
        rootfs_path: PathBuf,
        /// What the node measured, equal to the record's.
        rootfs_sha256: String,
    },
    /// The node cannot say which guest it boots.
    Unknown {
        /// The file the node looked at.
        rootfs_path: PathBuf,
        /// Why it cannot say.
        reason: UnknownGuest,
    },
}

/// Why a node cannot say which guest it boots. Each is "could not look" or
/// "looked and it did not match", never "fine" (ADR 0007 A-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cause", rename_all = "snake_case", deny_unknown_fields)]
pub enum UnknownGuest {
    /// No record beside the rootfs: installed by something other than a
    /// `nucleus setup` that writes one.
    NoRecord,
    /// A record that could not be read or was refused.
    RecordUnreadable {
        /// What went wrong.
        detail: String,
    },
    /// No rootfs at the path.
    NoRootfs,
    /// The rootfs could not be read.
    RootfsUnreadable {
        /// What went wrong.
        detail: String,
    },
    /// The rootfs is not the one the record describes.
    RootfsDiffers {
        /// The record's digest.
        recorded: String,
        /// The node's measurement.
        measured: String,
    },
    /// The rootfs file changed (or vanished) after the node measured it.
    RootfsChanged,
}

impl fmt::Display for UnknownGuest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRecord => write!(
                f,
                "there is no {GUEST_RELEASE_RECORD_FILE} beside its rootfs (a `nucleus setup` \
                 from this release writes one)"
            ),
            Self::RecordUnreadable { detail } => {
                write!(f, "its {GUEST_RELEASE_RECORD_FILE} was refused: {detail}")
            }
            Self::NoRootfs => write!(f, "it has no rootfs installed"),
            Self::RootfsUnreadable { detail } => write!(f, "its rootfs is unreadable: {detail}"),
            Self::RootfsDiffers { recorded, measured } => write!(
                f,
                "its rootfs (sha256 {measured}) is not the one its record names (sha256 \
                 {recorded}), so it was replaced after setup"
            ),
            Self::RootfsChanged => write!(
                f,
                "its rootfs changed after the node measured it at startup (restart the node to \
                 measure it again)"
            ),
        }
    }
}

/// The node's `/v1/health` reply. `guest` is absent from a node that predates
/// the report: a reader treats that as "not reported", never as a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeHealth {
    /// Always `ok` from a node that answers.
    pub status: String,
    /// The guest the node boots by default, as the node reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<NodeGuestReport>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "5699d939bd168c1fcc4aa8c217344f00b8cf2b7dffbf973af3d9440ce766a6bd";

    #[test]
    fn a_record_round_trips_and_refuses_what_it_cannot_vouch_for() {
        let record = GuestReleaseRecord::new(
            GuestOrigin::Release {
                version: "2.7.0".into(),
            },
            SHA,
        )
        .unwrap();
        let bytes = serde_json::to_vec(&record).unwrap();
        assert_eq!(GuestReleaseRecord::parse(&bytes).unwrap(), record);

        assert!(matches!(
            GuestReleaseRecord::new(GuestOrigin::LocalBuild, &SHA.to_uppercase()),
            Err(RecordError::Digest(_))
        ));
        let other_schema = String::from_utf8(bytes.clone()).unwrap().replace(
            GUEST_RELEASE_RECORD_SCHEMA,
            "nucleus.guest-release-record.v0",
        );
        assert!(matches!(
            GuestReleaseRecord::parse(other_schema.as_bytes()),
            Err(RecordError::Schema(_))
        ));
        let short = String::from_utf8(bytes).unwrap().replace(SHA, "abc");
        assert!(matches!(
            GuestReleaseRecord::parse(short.as_bytes()),
            Err(RecordError::Digest(_))
        ));
        assert!(matches!(
            GuestReleaseRecord::parse(b"{}"),
            Err(RecordError::Malformed(_))
        ));
    }

    #[test]
    fn the_flag_spelling_and_the_record_name_the_same_guest() {
        let pin = GuestOrigin::Release {
            version: "2.7.0".into(),
        };
        assert!(GuestOrigin::from_flag("2.7.0").same_guest(&pin));
        assert!(GuestOrigin::from_flag("v2.7.0").same_guest(&pin));
        assert!(!GuestOrigin::from_flag("2.6.0").same_guest(&pin));
        assert!(!GuestOrigin::from_flag(LOCAL_BUILD).same_guest(&pin));
        assert!(GuestOrigin::from_flag(LOCAL_BUILD).same_guest(&GuestOrigin::LocalBuild));
        assert!(!GuestOrigin::from_flag("latest").same_guest(&pin));
    }

    /// A node that predates the report answers `{"status":"ok"}`, which reads
    /// as `guest: None`, never as a release.
    #[test]
    fn an_old_nodes_health_reports_no_guest() {
        let old: NodeHealth = serde_json::from_str(r#"{"status":"ok"}"#).unwrap();
        assert_eq!(old.guest, None);
        let report = NodeHealth {
            status: "ok".into(),
            guest: Some(NodeGuestReport::Unknown {
                rootfs_path: "/var/lib/nucleus/artifacts/rootfs.ext4".into(),
                reason: UnknownGuest::NoRecord,
            }),
        };
        let back: NodeHealth =
            serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(back, report);
    }
}
