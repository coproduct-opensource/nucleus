//! The workload an image describes, with its user resolved to numbers.
//!
//! `User` is resolved against the **flattened** `/etc/passwd` and `/etc/group`
//! — the files the guest will actually have — never the host's.
//!
//! Resolution is a *report*, not a refusal: most base images leave `User`
//! unset (root), and importing one as a rootfs is ordinary. The outcome is an
//! [`ImageUser`], recorded in the import record. The refusal lives at the one
//! point that would run the image's own process as the workload:
//! [`WorkloadConfig::for_workload`] refuses uid 0 and a user that did not
//! resolve.

use crate::flatten::Flattened;

/// A non-root uid/gid pair an image's `User` resolved to.
///
/// The fields are private and deserialization re-checks them, so a `RunAs`
/// read back from an `import.json` cannot carry uid 0 either (C-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "RawRunAs")]
pub struct RunAs {
    uid: u32,
    gid: u32,
}

impl RunAs {
    /// `None` for uid 0: root is never a `RunAs`.
    fn new(uid: u32, gid: u32) -> Option<Self> {
        (uid != 0).then_some(Self { uid, gid })
    }

    /// Numeric uid; never 0.
    pub fn uid(self) -> u32 {
        self.uid
    }

    /// Numeric gid.
    pub fn gid(self) -> u32 {
        self.gid
    }
}

#[derive(serde::Deserialize)]
struct RawRunAs {
    uid: u32,
    gid: u32,
}

impl TryFrom<RawRunAs> for RunAs {
    type Error = &'static str;

    fn try_from(raw: RawRunAs) -> Result<Self, Self::Error> {
        Self::new(raw.uid, raw.gid).ok_or("run_as uid 0 is root, not a RunAs")
    }
}

/// Why an image's `User` names nobody the flattened tree knows.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnresolvableUser {
    /// A `User` that does not parse as `user[:group]`.
    #[error("it does not parse as user[:group]")]
    Malformed,
    /// A named user absent from the flattened `/etc/passwd`.
    #[error("user `{user}` is not in the image's /etc/passwd")]
    UserNotFound {
        /// The name.
        user: String,
    },
    /// A named group absent from the flattened `/etc/group`.
    #[error("group `{group}` is not in the image's /etc/group")]
    GroupNotFound {
        /// The name.
        group: String,
    },
    /// A numeric uid with no group given and no `/etc/passwd` entry to take one from.
    #[error("uid {uid} has no /etc/passwd entry and no explicit group; refusing to guess a gid")]
    NumericUserWithoutGroup {
        /// The uid.
        uid: u32,
    },
}

/// What an image's configured `User` resolves to in its own flattened tree.
///
/// Three cases, none of which fails an import (A-1: no `bool`, no folded
/// "could not resolve" into "root").
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ImageUser {
    /// A non-root uid/gid.
    Usable {
        /// The resolved ids.
        run_as: RunAs,
    },
    /// uid 0, explicitly or by leaving `User` unset.
    Root {
        /// The config's `User`, empty if unset.
        user: String,
    },
    /// A `User` the flattened `/etc/passwd`/`/etc/group` cannot resolve.
    Unresolvable {
        /// The config's `User`.
        user: String,
        /// Why.
        reason: UnresolvableUser,
    },
}

/// Why an image's own user cannot run as the workload.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WorkloadUserError {
    /// The image user is uid 0.
    #[error("image user `{user}` resolves to uid 0; a root workload is refused")]
    Root {
        /// The config's `User`, empty if unset.
        user: String,
    },
    /// The image user does not resolve in the image.
    #[error("image user `{user}` cannot be resolved: {reason}")]
    Unresolvable {
        /// The config's `User`.
        user: String,
        /// Why.
        reason: UnresolvableUser,
    },
}

/// The process an image asks the guest to run, recorded as data.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkloadConfig {
    /// What the image's `User` resolved to.
    pub user: ImageUser,
    /// `KEY=value` pairs, in the image's order.
    pub env: Vec<String>,
    /// The working directory, when the image sets one.
    pub working_dir: Option<String>,
    /// The entrypoint argv prefix.
    pub entrypoint: Vec<String>,
    /// The default arguments.
    pub cmd: Vec<String>,
}

impl WorkloadConfig {
    /// The ids to run the image's own process as the workload under.
    ///
    /// The one place a root or unresolvable image user is refused: a caller
    /// that runs the image's entrypoint as the workload must come through here.
    pub fn for_workload(&self) -> Result<RunAs, WorkloadUserError> {
        match &self.user {
            ImageUser::Usable { run_as } => Ok(*run_as),
            ImageUser::Root { user } => Err(WorkloadUserError::Root { user: user.clone() }),
            ImageUser::Unresolvable { user, reason } => Err(WorkloadUserError::Unresolvable {
                user: user.clone(),
                reason: reason.clone(),
            }),
        }
    }
}

/// An image config's process, with its `User` resolved against the flattened tree.
pub fn resolve_workload(
    config: &oci_spec::image::ImageConfiguration,
    rootfs: &Flattened,
) -> WorkloadConfig {
    let process = config.config().as_ref();
    let user = process
        .and_then(|c| c.user().as_ref())
        .map(String::as_str)
        .unwrap_or("");
    WorkloadConfig {
        user: resolve_user(user, rootfs),
        env: process.and_then(|c| c.env().clone()).unwrap_or_default(),
        working_dir: process
            .and_then(|c| c.working_dir().clone())
            .filter(|w| !w.is_empty()),
        entrypoint: process
            .and_then(|c| c.entrypoint().clone())
            .unwrap_or_default(),
        cmd: process.and_then(|c| c.cmd().clone()).unwrap_or_default(),
    }
}

/// A decimal id: digits only, fits in u32.
fn numeric(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// One `/etc/passwd` or `/etc/group` line's first, third and (for passwd) fourth fields.
struct DbEntry<'a> {
    name: &'a str,
    id: u32,
    primary_gid: Option<u32>,
}

fn database(file: Option<&[u8]>) -> Vec<DbEntry<'_>> {
    let Some(bytes) = file else {
        return Vec::new();
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let _password = fields.next()?;
            let id = numeric(fields.next()?)?;
            let primary_gid = fields.next().and_then(numeric);
            Some(DbEntry {
                name,
                id,
                primary_gid,
            })
        })
        .collect()
}

/// `user[:group]`, each a name or a number, to an [`ImageUser`].
pub(crate) fn resolve_user(user: &str, rootfs: &Flattened) -> ImageUser {
    let unresolvable = |reason| ImageUser::Unresolvable {
        user: user.to_owned(),
        reason,
    };
    if user.is_empty() {
        // An unset User runs as root.
        return ImageUser::Root {
            user: String::new(),
        };
    }
    let (user_part, group_part) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    if user_part.is_empty() || group_part.is_some_and(str::is_empty) {
        return unresolvable(UnresolvableUser::Malformed);
    }
    let passwd = database(rootfs.regular_file("etc/passwd"));
    let (uid, passwd_gid) = match numeric(user_part) {
        Some(uid) => (
            uid,
            passwd
                .iter()
                .find(|e| e.id == uid)
                .and_then(|e| e.primary_gid),
        ),
        None => match passwd.iter().find(|e| e.name == user_part) {
            Some(entry) => (entry.id, entry.primary_gid),
            None => {
                return unresolvable(UnresolvableUser::UserNotFound {
                    user: user_part.to_owned(),
                });
            }
        },
    };
    if uid == 0 {
        // Root whatever the group says: the group cannot make uid 0 safe.
        return ImageUser::Root {
            user: user.to_owned(),
        };
    }
    let gid = match group_part {
        Some(group) => match numeric(group) {
            Some(gid) => gid,
            None => match database(rootfs.regular_file("etc/group"))
                .iter()
                .find(|e| e.name == group)
            {
                Some(entry) => entry.id,
                None => {
                    return unresolvable(UnresolvableUser::GroupNotFound {
                        group: group.to_owned(),
                    });
                }
            },
        },
        None => match passwd_gid {
            Some(gid) => gid,
            None => return unresolvable(UnresolvableUser::NumericUserWithoutGroup { uid }),
        },
    };
    match RunAs::new(uid, gid) {
        Some(run_as) => ImageUser::Usable { run_as },
        // uid 0 returned above; kept exhaustive rather than unreachable.
        None => ImageUser::Root {
            user: user.to_owned(),
        },
    }
}
