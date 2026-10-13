//! Secrets earlier releases of `nucleus setup` stored, and taking them back out.
//!
//! `setup` used to mint static 32-byte HMAC secrets and keep them in the macOS
//! Keychain (service `com.nucleus.cli`) or, elsewhere, as one `0600` file per
//! account under `~/.config/nucleus/secrets/`, with rotation dates beside them
//! in `~/.config/nucleus/secrets-metadata.json`. Every one of those secrets has
//! since lost its consumer, so this module can no longer create, read or rotate
//! one: it can only say whether a retired item is still stored, and delete it.
//! A static shared secret with no reader is only something to leak (#3294,
//! #3436).

use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "com.nucleus.cli";

/// Accounts earlier releases stored and nothing reads any more.
///
/// - `node-auth-secret` was the HMAC key for nucleus-node's own HTTP/gRPC API.
///   Move B made that API mTLS-only; the CLI and `doctor` reach the node with
///   the provisioned client identity alone (#3294).
/// - `proxy-auth-secret` and `approval-secret` were the tool-proxy's request
///   and approval HMAC keys. The shared-secret tier was deleted (#3391), the
///   node refuses both flags by name, and `node.env` no longer carries them
///   (`provision::retired_env`). The tool-proxy's legacy approval key comes
///   from the guest's own `/etc/nucleus/approval.secret`, never from here
///   (#3436).
pub const RETIRED_ACCOUNTS: &[&str] = &["node-auth-secret", "proxy-auth-secret", "approval-secret"];

/// Whether each retired account is still stored, in [`RETIRED_ACCOUNTS`]
/// order. An `Err` is "could not look", never "absent" (ADR 0007 A-1).
pub fn retired_present() -> Vec<(&'static str, Result<bool>)> {
    RETIRED_ACCOUNTS
        .iter()
        .map(|account| (*account, present(account)))
        .collect()
}

/// Delete every retired account still stored, and its rotation metadata.
/// Returns the accounts that were there to delete; any failure other than
/// "already gone" is an error.
pub fn remove_retired() -> Result<Vec<&'static str>> {
    let mut removed = Vec::new();
    for account in RETIRED_ACCOUNTS {
        if delete(account)? {
            removed.push(*account);
        }
    }
    MetadataFile::default_location()?.remove(RETIRED_ACCOUNTS)?;
    Ok(removed)
}

#[cfg(target_os = "macos")]
fn present(account: &str) -> Result<bool> {
    use security_framework::passwords::get_generic_password;

    match get_generic_password(KEYCHAIN_SERVICE, account) {
        Ok(_) => Ok(true),
        Err(e) if e.code() == -25300 => Ok(false), // errSecItemNotFound
        Err(e) => Err(anyhow!("Keychain error for {account}: {e}")),
    }
}

#[cfg(not(target_os = "macos"))]
fn present(account: &str) -> Result<bool> {
    FileSecrets::default_location()?.present(account)
}

#[cfg(target_os = "macos")]
fn delete(account: &str) -> Result<bool> {
    use security_framework::passwords::delete_generic_password;

    match delete_generic_password(KEYCHAIN_SERVICE, account) {
        Ok(()) => Ok(true),
        Err(e) if e.code() == -25300 => Ok(false), // errSecItemNotFound
        Err(e) => Err(anyhow!("Failed to delete {account} from Keychain: {e}")),
    }
}

#[cfg(not(target_os = "macos"))]
fn delete(account: &str) -> Result<bool> {
    FileSecrets::default_location()?.delete(account)
}

/// `~/.config/nucleus`, where the non-Keychain store and the metadata live.
fn nucleus_config_dir() -> Result<PathBuf> {
    let config_dir =
        dirs::config_dir().ok_or_else(|| anyhow!("Could not determine config directory"))?;
    Ok(config_dir.join("nucleus"))
}

/// The non-macOS store: one file per account in one directory.
#[cfg_attr(target_os = "macos", allow(dead_code))]
struct FileSecrets {
    dir: PathBuf,
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
impl FileSecrets {
    fn default_location() -> Result<Self> {
        Ok(Self {
            dir: nucleus_config_dir()?.join("secrets"),
        })
    }

    fn present(&self, account: &str) -> Result<bool> {
        let path = self.dir.join(account);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("checking {}", path.display())),
        }
    }

    fn delete(&self, account: &str) -> Result<bool> {
        let path = self.dir.join(account);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }
}

/// The rotation-date file earlier releases kept beside the secrets. Not
/// sensitive, but it names secrets that no longer exist.
struct MetadataFile {
    path: PathBuf,
}

impl MetadataFile {
    fn default_location() -> Result<Self> {
        Ok(Self {
            path: nucleus_config_dir()?.join("secrets-metadata.json"),
        })
    }

    /// Drop `accounts`' entries, keeping any other. A file left with no entry
    /// is deleted. An absent file is nothing to do; an unreadable or
    /// unparseable one is an error, never "nothing recorded".
    fn remove(&self, accounts: &[&str]) -> Result<()> {
        let body = match std::fs::read_to_string(&self.path) {
            Ok(body) => body,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.path.display())),
        };
        let mut entries: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&body)
                .with_context(|| format!("parsing {}", self.path.display()))?;
        let before = entries.len();
        entries.retain(|name, _| !accounts.contains(&name.as_str()));
        if entries.len() == before {
            return Ok(());
        }
        if entries.is_empty() {
            return remove_file(&self.path);
        }
        std::fs::write(&self.path, serde_json::to_string_pretty(&entries)?)
            .with_context(|| format!("writing {}", self.path.display()))
    }
}

fn remove_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #3436: every account an earlier `setup` minted is retired. The two
    /// tool-proxy HMAC keys outlived their consumer (#3391) and were still
    /// created on every run.
    #[test]
    fn every_account_setup_ever_minted_is_retired() {
        for account in ["node-auth-secret", "proxy-auth-secret", "approval-secret"] {
            assert!(
                RETIRED_ACCOUNTS.contains(&account),
                "{account}: nothing reads it, so it must be retired"
            );
        }
    }

    /// The file store deletes exactly the retired accounts, reports what it
    /// found, and a second pass finds nothing. Explicit paths: neither the
    /// real Keychain nor the user's config directory is touched.
    #[test]
    fn file_store_deletes_only_retired_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecrets {
            dir: dir.path().to_path_buf(),
        };
        for account in ["proxy-auth-secret", "approval-secret", "unrelated"] {
            std::fs::write(dir.path().join(account), b"x").unwrap();
        }
        assert!(store.present("proxy-auth-secret").unwrap());
        assert!(!store.present("node-auth-secret").unwrap());

        let removed: Vec<_> = RETIRED_ACCOUNTS
            .iter()
            .filter(|a| store.delete(a).unwrap())
            .collect();
        assert_eq!(removed, [&"proxy-auth-secret", &"approval-secret"]);
        for account in RETIRED_ACCOUNTS {
            assert!(!store.present(account).unwrap(), "{account} survived");
            assert!(!store.delete(account).unwrap(), "{account} deleted twice");
        }
        assert!(
            dir.path().join("unrelated").exists(),
            "a live file was deleted"
        );
    }

    /// "Could not look" is an error, not "absent" (A-1): a store directory
    /// that is a file cannot be searched.
    #[test]
    fn a_store_that_cannot_be_read_is_an_error_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("secrets");
        std::fs::write(&not_a_dir, b"").unwrap();
        let store = FileSecrets { dir: not_a_dir };
        assert!(store.present("approval-secret").is_err());
        assert!(store.delete("approval-secret").is_err());
    }

    #[test]
    fn metadata_drops_retired_entries_and_keeps_others() {
        let dir = tempfile::tempdir().unwrap();
        let file = MetadataFile {
            path: dir.path().join("secrets-metadata.json"),
        };
        // Absent: nothing to do.
        file.remove(RETIRED_ACCOUNTS).unwrap();
        assert!(!file.path.exists());

        std::fs::write(
            &file.path,
            r#"{"proxy-auth-secret":{"version":1},"approval-secret":{"version":2},"other":{"version":3}}"#,
        )
        .unwrap();
        file.remove(RETIRED_ACCOUNTS).unwrap();
        let left: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&file.path).unwrap()).unwrap();
        assert_eq!(left, serde_json::json!({"other": {"version": 3}}));

        // Only retired entries: the file goes.
        std::fs::write(&file.path, r#"{"approval-secret":{"version":1}}"#).unwrap();
        file.remove(RETIRED_ACCOUNTS).unwrap();
        assert!(!file.path.exists());

        // Unparseable is an error, never "nothing recorded".
        std::fs::write(&file.path, "not json").unwrap();
        assert!(file.remove(RETIRED_ACCOUNTS).is_err());
    }
}
