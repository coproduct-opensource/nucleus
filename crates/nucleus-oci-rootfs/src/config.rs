//! The workload an image describes, with its user resolved to numbers.
//!
//! `User` is resolved against the **flattened** `/etc/passwd` and `/etc/group`
//! — the files the guest will actually have — never the host's. A workload
//! that would run as uid 0 is refused, and so is a name that is not there.

use crate::error::ImportError;
use crate::flatten::Flattened;

/// The process an image asks the guest to run.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkloadConfig {
    /// Numeric uid; never 0.
    pub uid: u32,
    /// Numeric gid.
    pub gid: u32,
    /// `KEY=value` pairs, in the image's order.
    pub env: Vec<String>,
    /// The working directory, when the image sets one.
    pub working_dir: Option<String>,
    /// The entrypoint argv prefix.
    pub entrypoint: Vec<String>,
    /// The default arguments.
    pub cmd: Vec<String>,
}

/// A `User` value from an image config, resolved against the flattened tree.
pub fn resolve_workload(
    config: &oci_spec::image::ImageConfiguration,
    rootfs: &Flattened,
) -> Result<WorkloadConfig, ImportError> {
    let process = config.config().as_ref();
    let user = process
        .and_then(|c| c.user().as_ref())
        .map(String::as_str)
        .unwrap_or("");
    let (uid, gid) = resolve_user(user, rootfs)?;
    Ok(WorkloadConfig {
        uid,
        gid,
        env: process.and_then(|c| c.env().clone()).unwrap_or_default(),
        working_dir: process
            .and_then(|c| c.working_dir().clone())
            .filter(|w| !w.is_empty()),
        entrypoint: process
            .and_then(|c| c.entrypoint().clone())
            .unwrap_or_default(),
        cmd: process.and_then(|c| c.cmd().clone()).unwrap_or_default(),
    })
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

/// `user[:group]`, each a name or a number, to `(uid, gid)`.
pub(crate) fn resolve_user(user: &str, rootfs: &Flattened) -> Result<(u32, u32), ImportError> {
    if user.is_empty() {
        // An unset User runs as root.
        return Err(ImportError::RootWorkload {
            user: String::new(),
        });
    }
    let (user_part, group_part) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    if user_part.is_empty() || group_part.is_some_and(str::is_empty) {
        return Err(ImportError::MalformedUser {
            user: user.to_owned(),
        });
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
        None => {
            let entry = passwd.iter().find(|e| e.name == user_part).ok_or_else(|| {
                ImportError::UserNotFound {
                    user: user_part.to_owned(),
                }
            })?;
            (entry.id, entry.primary_gid)
        }
    };
    if uid == 0 {
        return Err(ImportError::RootWorkload {
            user: user.to_owned(),
        });
    }
    let gid = match group_part {
        Some(group) => match numeric(group) {
            Some(gid) => gid,
            None => database(rootfs.regular_file("etc/group"))
                .iter()
                .find(|e| e.name == group)
                .map(|e| e.id)
                .ok_or_else(|| ImportError::GroupNotFound {
                    group: group.to_owned(),
                })?,
        },
        None => passwd_gid.ok_or(ImportError::NumericUserWithoutGroup { uid })?,
    };
    Ok((uid, gid))
}
