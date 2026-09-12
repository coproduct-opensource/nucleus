//! Receipts, stored under the key they are about.
//!
//! # The join this closes
//!
//! `nucleus-action-key` derives what a gate reads; `nucleus-node` produces a
//! host-signed receipt saying what a gate did. Until this crate, **nothing put
//! one under the other**, so the two halves were a key with nowhere to go and a
//! receipt nobody could find.
//!
//! # The invariant: the store does not believe its own index
//!
//! A file store keyed by hex is a lookup table, and a lookup table can be
//! wrong — a bad write, a partial copy, a directory restored from the wrong
//! backup, a key derivation that changed underneath the stored blobs. Every one
//! of those hands back a receipt for a DIFFERENT gate, which is the single
//! failure that makes a receipt cache worse than no cache: a green check citing
//! work that was done on something else.
//!
//! So the receipt names its own key, and [`ReceiptStore::get`] checks that the
//! blob it found agrees with the key it was asked for. The filename is a hint;
//! the content is the authority. A mismatch is [`StoreError::Mislabelled`] and
//! is never returned as a hit.
//!
//! That check is cheap and it is the whole point: without it this crate is a
//! `HashMap` with extra steps, and the design's soundness rests on a filename.
//!
//! # What it does not do
//!
//! Verify the receipt's signature. That is `pod_authority::verify_pod_receipt`'s
//! job and it needs the signer's public key, which a store has no business
//! holding. A caller that skips it has an unsigned cache, and this crate cannot
//! tell it so — stated here rather than implied by silence.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use nucleus_action_key::ActionKey;
use std::path::PathBuf;

/// The field a stored receipt must carry, naming the key it is filed under.
const KEY_FIELD: &str = "action_key";

/// Why a lookup did not produce a receipt.
#[derive(Debug)]
pub enum StoreError {
    /// The blob under this key says it is about a different one. NOT a miss:
    /// a miss means "run the gate", and this means "something is wrong with
    /// the store", and treating the second as the first would quietly re-run
    /// forever while the corruption stayed.
    Mislabelled { asked: String, found: String },
    /// The blob is not JSON, or carries no `action_key`. Also not a miss: a
    /// receipt that cannot say what it is about is not one this store may
    /// hand back.
    Unreadable(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Mislabelled { asked, found } => write!(
                f,
                "the receipt filed under {asked} says it is about {found} — refusing to serve it: \
                 a receipt for another gate is a green check citing work done on something else"
            ),
            StoreError::Unreadable(why) => write!(
                f,
                "a stored receipt could not be read well enough to confirm what it is about: {why}"
            ),
        }
    }
}

impl std::error::Error for StoreError {}

/// A content-addressed store of receipts on local disk.
pub struct ReceiptStore {
    root: PathBuf,
}

impl ReceiptStore {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path_for(&self, key: &ActionKey) -> PathBuf {
        let hex = key.to_hex();
        // Two levels of fan-out: a flat directory of tens of thousands of
        // entries is slow to list and unpleasant to inspect by hand, and the
        // prefix is free.
        let (a, b) = hex.split_at(2);
        let (b, _) = b.split_at(2);
        self.root.join(a).join(b).join(format!("{hex}.json"))
    }

    /// File a receipt under `key`.
    ///
    /// Refuses a receipt that names a different key, so a mislabelled blob
    /// cannot enter the store in the first place. Checking on the way in AND on
    /// the way out is deliberate: the write check catches a caller's mistake,
    /// and the read check catches everything that happens to a file after it is
    /// written, which is the larger set.
    pub fn put(&self, key: &ActionKey, receipt_json: &str) -> Result<()> {
        match declared_key(receipt_json) {
            Ok(found) if found == key.to_hex() => {}
            Ok(found) => {
                return Err(StoreError::Mislabelled {
                    asked: key.to_hex(),
                    found,
                }
                .into());
            }
            Err(e) => return Err(e.into()),
        }
        let path = self.path_for(key);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        // Write-then-rename: a reader must never see half a receipt, and a
        // crash mid-write must leave the previous one intact.
        let tmp = path.with_extension("json.partial");
        std::fs::write(&tmp, receipt_json)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("publishing {}", path.display()))?;
        Ok(())
    }

    /// The receipt filed under `key`, if there is one that agrees it is about
    /// `key`.
    ///
    /// `Ok(None)` is a miss — run the gate. An `Err` is a store that cannot be
    /// trusted, which is a different thing and must not be silently retried.
    pub fn get(&self, key: &ActionKey) -> Result<Option<String>> {
        let path = self.path_for(key);
        let body = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let found = declared_key(&body)?;
        if found != key.to_hex() {
            return Err(StoreError::Mislabelled {
                asked: key.to_hex(),
                found,
            }
            .into());
        }
        Ok(Some(body))
    }

    /// Where a key's receipt would live. Exposed so an operator can look.
    #[must_use]
    pub fn location(&self, key: &ActionKey) -> PathBuf {
        self.path_for(key)
    }
}

/// The key a receipt says it is about.
fn declared_key(receipt_json: &str) -> Result<String, StoreError> {
    let v: serde_json::Value = serde_json::from_str(receipt_json)
        .map_err(|e| StoreError::Unreadable(format!("not JSON: {e}")))?;
    v.get(KEY_FIELD)
        .and_then(|k| k.as_str())
        .map(str::to_string)
        .ok_or_else(|| StoreError::Unreadable(format!("no `{KEY_FIELD}` field")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_action_key::{ActionKey, Inputs, ReadEntry};

    /// A real derived key. Deliberately NOT a byte constructor: `derive`'s
    /// exhaustive destructure is the only way a key is meant to come into
    /// being, and a `from_bytes` added for tests would be a hole straight
    /// through it that production code could reach for later.
    fn key(context: &str) -> ActionKey {
        ActionKey::derive(&Inputs {
            context: context.to_string(),
            read_set: vec![ReadEntry {
                path: format!("src/{context}.rs"),
                digest: [7u8; 32],
            }],
            gate: vec![ReadEntry {
                path: format!("scripts/{context}.sh"),
                digest: [9u8; 32],
            }],
            toolchain: vec![("rust".into(), "1.90.0".into())],
        })
    }

    fn receipt_for(k: &ActionKey) -> String {
        format!(
            r#"{{"action_key":"{}","verdict":"pass","exit_status":0}}"#,
            k.to_hex()
        )
    }

    #[test]
    fn a_receipt_filed_under_a_key_comes_back_under_that_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path().to_path_buf());
        let k = key("manifest-guards");
        store.put(&k, &receipt_for(&k)).unwrap();
        let got = store.get(&k).unwrap().expect("the receipt just filed");
        assert!(got.contains(&k.to_hex()));
    }

    #[test]
    fn an_unknown_key_is_a_miss_not_an_error() {
        // The distinction the whole error type exists for: a miss means "run
        // the gate", and must not look like a broken store.
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path().to_path_buf());
        assert!(store.get(&key("never-filed")).unwrap().is_none());
    }

    #[test]
    fn a_receipt_naming_a_different_key_is_refused_on_the_way_in() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path().to_path_buf());
        let asked = key("clippy");
        let other = key("rustfmt");
        let e = store.put(&asked, &receipt_for(&other)).unwrap_err();
        assert!(
            e.to_string().contains("refusing to serve it"),
            "got: {e}"
        );
        assert!(
            !store.location(&asked).exists(),
            "a refused put must not leave a file behind"
        );
    }

    /// **The test that makes this crate worth more than a `HashMap`.**
    ///
    /// It reaches past `put` and writes the wrong receipt to the right path by
    /// hand — which is exactly what a bad restore, a partial copy or a changed
    /// key derivation does. If `get` trusted the filename, this returns a
    /// receipt for the WRONG gate and the test goes green.
    #[test]
    fn a_receipt_mislabelled_on_disk_is_never_served_as_a_hit() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path().to_path_buf());
        let asked = key("clippy");
        let other = key("rustfmt");

        let path = store.location(&asked);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, receipt_for(&other)).unwrap();

        let e = store
            .get(&asked)
            .expect_err("a receipt about another gate must not be a hit");
        let msg = e.to_string();
        assert!(msg.contains(&asked.to_hex()), "names what was asked: {msg}");
        assert!(msg.contains(&other.to_hex()), "names what was found: {msg}");
    }

    #[test]
    fn a_receipt_that_cannot_say_what_it_is_about_is_not_a_hit() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path().to_path_buf());
        let k = key("gate-with-no-key-field");
        let path = store.location(&k);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, r#"{"verdict":"pass"}"#).unwrap();
        assert!(store.get(&k).is_err());

        std::fs::write(&path, "not json at all").unwrap();
        assert!(store.get(&k).is_err());
    }

    #[test]
    fn a_partial_write_is_not_visible_as_a_receipt() {
        // put() writes to `.json.partial` and renames. A crash leaves the
        // partial file, which must not be found by a lookup.
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path().to_path_buf());
        let k = key("interrupted");
        let path = store.location(&k);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path.with_extension("json.partial"), r#"{"action_k"#).unwrap();
        assert!(store.get(&k).unwrap().is_none());
    }

    #[test]
    fn different_keys_do_not_share_a_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path().to_path_buf());
        assert_ne!(store.location(&key("a")), store.location(&key("b")));
    }
}
