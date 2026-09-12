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
//! # What it stores
//!
//! A signed [`nucleus_receipt::Receipt`] carrying exactly one
//! [`CiVerdict`](nucleus_ci_verdict::CiVerdict). The store reads the action key
//! out of that verdict, which is why it knows the shape rather than holding an
//! opaque blob: a store that cannot read what it holds cannot check that it
//! holds the right thing.
//!
//! # What it does not do
//!
//! Verify the signature. That needs the signer's public key, which a store has
//! no business holding — the same key would then be reachable from anything
//! that can reach the cache. Callers verify with
//! [`nucleus_receipt::Receipt::verify`] before trusting a verdict, and a caller
//! that skips it has an unsigned cache. This crate cannot tell it so, which is
//! why it is said here rather than implied by silence.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use nucleus_action_key::ActionKey;
use nucleus_ci_verdict::CiVerdict;
use nucleus_receipt::Receipt;
use std::path::PathBuf;

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
    pub fn put(&self, key: &ActionKey, receipt: &Receipt) -> Result<()> {
        let verdict =
            CiVerdict::from_receipt(receipt).map_err(|e| StoreError::Unreadable(e.to_string()))?;
        if verdict.action_key != key.to_hex() {
            return Err(StoreError::Mislabelled {
                asked: key.to_hex(),
                found: verdict.action_key,
            }
            .into());
        }
        let receipt_json =
            serde_json::to_string(receipt).context("serializing a receipt for the store")?;
        let path = self.path_for(key);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        // Write-then-rename: a reader must never see half a receipt, and a
        // crash mid-write must leave the previous one intact.
        let tmp = path.with_extension("json.partial");
        std::fs::write(&tmp, &receipt_json)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("publishing {}", path.display()))?;
        Ok(())
    }

    /// The receipt filed under `key`, if there is one that agrees it is about
    /// `key`.
    ///
    /// `Ok(None)` is a miss — run the gate. An `Err` is a store that cannot be
    /// trusted, which is a different thing and must not be silently retried.
    pub fn get(&self, key: &ActionKey) -> Result<Option<Receipt>> {
        let path = self.path_for(key);
        let body = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let (receipt, found) = parse(&body)?;
        if found != key.to_hex() {
            return Err(StoreError::Mislabelled {
                asked: key.to_hex(),
                found,
            }
            .into());
        }
        Ok(Some(receipt))
    }

    /// Where a key's receipt would live. Exposed so an operator can look.
    #[must_use]
    pub fn location(&self, key: &ActionKey) -> PathBuf {
        self.path_for(key)
    }
}

/// Parse a stored blob into the receipt and the key its verdict claims.
///
/// Both failures are [`StoreError::Unreadable`] rather than a miss: a blob
/// this store cannot read well enough to confirm what it is about is not one
/// it may hand back.
fn parse(blob: &str) -> Result<(Receipt, String), StoreError> {
    let receipt: Receipt = serde_json::from_str(blob)
        .map_err(|e| StoreError::Unreadable(format!("not a receipt envelope: {e}")))?;
    let verdict = CiVerdict::from_receipt(&receipt)
        .map_err(|e| StoreError::Unreadable(e.to_string()))?;
    let key = verdict.action_key.clone();
    Ok((receipt, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_action_key::{ActionKey, Inputs, ReadEntry};
    use nucleus_ci_verdict::Conclusion;

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

    /// A real signed envelope carrying a real verdict, because the store now
    /// reads the key out of the verdict and a hand-rolled JSON blob would be
    /// testing a different function.
    fn receipt_for(k: &ActionKey) -> nucleus_receipt::Receipt {
        let verdict = CiVerdict {
            action_key: k.to_hex(),
            context: "The Gate".into(),
            tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
            conclusion: Conclusion::Success,
            exit_status: 0,
            log_digest: "ab".repeat(32),
            pod_id: "pod-1".into(),
            certificate: None,
        };
        nucleus_receipt::Receipt::sign(
            nucleus_receipt::Session {
                session_id: "spiffe://nucleus/node/1".into(),
                issuer_kid: "kid-1".into(),
                issued_at_micros: 1_757_000_000_000_000,
                parent_chain: vec![],
            },
            vec![verdict.to_projection()],
            &ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
        )
    }

    #[test]
    fn a_receipt_filed_under_a_key_comes_back_under_that_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::new(dir.path().to_path_buf());
        let k = key("manifest-guards");
        store.put(&k, &receipt_for(&k)).unwrap();
        let got = store.get(&k).unwrap().expect("the receipt just filed");
        let v = CiVerdict::from_receipt(&got).expect("carries a verdict");
        assert_eq!(v.action_key, k.to_hex());
        // The envelope must still verify after a disk round trip — a store
        // that quietly reserialized a receipt into something that no longer
        // verifies would be useless in exactly the way that is hardest to see.
        got.verify(&ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes())
            .expect("a stored receipt must still verify when it comes back");
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
        std::fs::write(&path, serde_json::to_string(&receipt_for(&other)).unwrap()).unwrap();

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
