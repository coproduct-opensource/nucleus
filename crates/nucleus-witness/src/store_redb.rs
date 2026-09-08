//! Durable [`OriginStore`] on redb (feature `persist`).
//!
//! The in-memory store documents its own gap: a restart resets every origin's
//! last-cosigned position to `None`, so a producer could replay an old
//! checkpoint as a "first submission" and obtain a fresh cosignature over a
//! stale view. This store keeps the position on disk, and every `advance` is
//! a compare-and-swap inside one redb write transaction (write transactions
//! are serialized), so the monotonicity the status matrix relies on survives
//! both restarts and concurrent submissions.
//!
//! Fail-closed on I/O: an error while reading makes the origin look unknown
//! (the handler answers 404, never cosigns), and an error while advancing
//! returns `false` (the handler answers 409, never cosigns).

use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::store::{CosignedPosition, OriginRecord, OriginStore, TrustedLogKey};

/// `origin -> encoded OriginRecord`.
const ORIGINS: TableDefinition<&str, &[u8]> = TableDefinition::new("witness_origins_v1");

/// Errors from opening the database or registering an origin.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database could not be opened or written.
    #[error("redb: {0}")]
    Db(String),
    /// A stored record did not decode (corruption or a foreign schema).
    #[error("corrupt origin record for {0}")]
    Corrupt(String),
}

impl From<redb::Error> for StoreError {
    fn from(e: redb::Error) -> Self {
        StoreError::Db(e.to_string())
    }
}

/// Durable per-origin witness state.
pub struct RedbStore {
    db: Database,
}

// ── Encoding: length-prefixed, no separators, versioned by the table name ───

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn encode(rec: &OriginRecord) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, rec.trusted_log_keys.len() as u32);
    for k in &rec.trusted_log_keys {
        put_u32(&mut out, k.key_name.len() as u32);
        out.extend_from_slice(k.key_name.as_bytes());
        out.extend_from_slice(&k.pubkey);
    }
    match rec.last_cosigned {
        None => out.push(0),
        Some(p) => {
            out.push(1);
            out.extend_from_slice(&p.size.to_be_bytes());
            out.extend_from_slice(&p.root);
        }
    }
    out
}

fn take<'a>(buf: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if buf.len() < n {
        return None;
    }
    let (head, rest) = buf.split_at(n);
    *buf = rest;
    Some(head)
}

fn decode(mut buf: &[u8]) -> Option<OriginRecord> {
    let n = u32::from_be_bytes(take(&mut buf, 4)?.try_into().ok()?) as usize;
    let mut trusted_log_keys = Vec::with_capacity(n.min(64));
    for _ in 0..n {
        let len = u32::from_be_bytes(take(&mut buf, 4)?.try_into().ok()?) as usize;
        let name = std::str::from_utf8(take(&mut buf, len)?).ok()?.to_string();
        let pubkey: [u8; 32] = take(&mut buf, 32)?.try_into().ok()?;
        trusted_log_keys.push(TrustedLogKey {
            key_name: name,
            pubkey,
        });
    }
    let last_cosigned = match take(&mut buf, 1)? {
        [0] => None,
        [1] => {
            let size = u64::from_be_bytes(take(&mut buf, 8)?.try_into().ok()?);
            let root: [u8; 32] = take(&mut buf, 32)?.try_into().ok()?;
            Some(CosignedPosition { size, root })
        }
        _ => return None,
    };
    if !buf.is_empty() {
        return None;
    }
    Some(OriginRecord {
        trusted_log_keys,
        last_cosigned,
    })
}

impl RedbStore {
    /// Open (or create) the store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(|e| StoreError::Db(e.to_string()))?;
        // Create the table so first reads do not error on a missing table.
        let txn = db
            .begin_write()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        txn.open_table(ORIGINS)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        txn.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(Self { db })
    }

    /// Register an origin with its trusted log keys and (optionally) a
    /// starting last-cosigned position. Overwrites an existing record.
    pub fn add_origin(
        &self,
        origin: impl Into<String>,
        trusted_log_keys: Vec<TrustedLogKey>,
        last_cosigned: Option<CosignedPosition>,
    ) -> Result<(), StoreError> {
        let origin = origin.into();
        let rec = OriginRecord {
            trusted_log_keys,
            last_cosigned,
        };
        let txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        {
            let mut table = txn
                .open_table(ORIGINS)
                .map_err(|e| StoreError::Db(e.to_string()))?;
            table
                .insert(origin.as_str(), encode(&rec).as_slice())
                .map_err(|e| StoreError::Db(e.to_string()))?;
        }
        txn.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(())
    }
}

impl OriginStore for RedbStore {
    fn get(&self, origin: &str) -> Option<OriginRecord> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(ORIGINS).ok()?;
        let v = table.get(origin).ok()??;
        decode(v.value())
    }

    fn advance(
        &self,
        origin: &str,
        expected: Option<CosignedPosition>,
        pos: CosignedPosition,
    ) -> bool {
        // One write transaction = one serialized CAS.
        let Ok(txn) = self.db.begin_write() else {
            return false;
        };
        let ok = {
            let Ok(mut table) = txn.open_table(ORIGINS) else {
                return false;
            };
            let current = match table.get(origin) {
                Ok(Some(v)) => decode(v.value()),
                _ => None,
            };
            match current {
                Some(mut rec) if rec.last_cosigned == expected => {
                    rec.last_cosigned = Some(pos);
                    table.insert(origin, encode(&rec).as_slice()).is_ok()
                }
                _ => false,
            }
        };
        if !ok {
            return false;
        }
        txn.commit().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> TrustedLogKey {
        TrustedLogKey {
            key_name: format!("k{b}"),
            pubkey: [b; 32],
        }
    }

    fn fresh_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nucleus-witness-{tag}-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        p
    }

    #[test]
    fn record_encoding_round_trips() {
        let rec = OriginRecord {
            trusted_log_keys: vec![key(1), key(2)],
            last_cosigned: Some(CosignedPosition {
                size: 7,
                root: [9u8; 32],
            }),
        };
        let bytes = encode(&rec);
        let back = decode(&bytes).expect("decodes");
        assert_eq!(back.trusted_log_keys, rec.trusted_log_keys);
        assert_eq!(back.last_cosigned, rec.last_cosigned);
        // Truncated or padded bytes never decode to a record.
        assert!(decode(&bytes[..bytes.len() - 1]).is_none());
        let mut padded = bytes.clone();
        padded.push(0);
        assert!(decode(&padded).is_none());
    }

    #[test]
    fn unknown_origin_returns_none_and_cannot_advance() {
        let path = fresh_path("unknown");
        let store = RedbStore::open(&path).unwrap();
        assert!(store.get("ghost").is_none());
        assert!(!store.advance(
            "ghost",
            None,
            CosignedPosition {
                size: 1,
                root: [0u8; 32]
            }
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn advance_is_a_compare_and_swap() {
        let path = fresh_path("cas");
        let store = RedbStore::open(&path).unwrap();
        store.add_origin("o", vec![key(1)], None).unwrap();
        let pos = CosignedPosition {
            size: 5,
            root: [1u8; 32],
        };
        assert!(store.advance("o", None, pos));
        // The same first-submission CAS now fails: the state moved.
        assert!(!store.advance("o", None, pos));
        let pos2 = CosignedPosition {
            size: 9,
            root: [2u8; 32],
        };
        assert!(store.advance("o", Some(pos), pos2));
        assert_eq!(store.get("o").unwrap().last_cosigned, Some(pos2));
        let _ = std::fs::remove_file(path);
    }

    /// The property the in-memory store cannot have: the position survives a restart, so a
    /// replayed "first submission" is refused after reopening.
    #[test]
    fn last_cosigned_position_survives_reopen() {
        let path = fresh_path("reopen");
        let pos = CosignedPosition {
            size: 5,
            root: [1u8; 32],
        };
        {
            let store = RedbStore::open(&path).unwrap();
            store.add_origin("o", vec![key(1)], None).unwrap();
            assert!(store.advance("o", None, pos));
        }
        let store = RedbStore::open(&path).unwrap();
        assert_eq!(store.get("o").unwrap().last_cosigned, Some(pos));
        assert!(
            !store.advance("o", None, pos),
            "replay after restart must be refused"
        );
        let _ = std::fs::remove_file(path);
    }
}
