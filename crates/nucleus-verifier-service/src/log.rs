//! Append-only verification log — iter-1.
//!
//! The verifier service commits to every successful verification by
//! appending a row to `log_entries` whose `entry_hash` chains to the
//! previous row's `entry_hash`. Given the current tip, anyone can
//! replay the chain forward from genesis and confirm the log has
//! been faithfully maintained — a cheap analogue of an RFC 9162
//! Merkle root.
//!
//! # Iter-1 scope
//!
//! - Append-only chain (SHA-256 chain hash, not a Merkle root)
//! - `GET /v1/log/size` — total entries
//! - `GET /v1/log/sth` — `{tree_size, root_hash_hex, ts_ms}` UNSIGNED
//!
//! # Iter-2 (task #94)
//!
//! - Upgrade `root_hash_hex` to a real RFC 9162 Merkle root
//! - Sign the STH with the verifier's Ed25519 key
//! - `GET /v1/log/inclusion-proof?leaf=...`
//! - `GET /v1/log/consistency-proof?from=...&to=...`
//! - tlog-tiles static serving (Go-sumdb-compatible)

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};

/// All-zero "genesis" hash for the very first entry's `prev_hash`.
const ZERO_HASH: [u8; 32] = [0u8; 32];

/// Compute the next entry's hash from `(prev_hash, envelope_hash_bytes,
/// ts_ms)`. Stable across versions; this is the chain primitive.
pub fn compute_entry_hash(prev_hash: &[u8; 32], envelope_hash_hex: &str, ts_ms: i64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev_hash);
    h.update(envelope_hash_hex.as_bytes());
    h.update(ts_ms.to_be_bytes());
    h.finalize().into()
}

/// Append a verification leaf to the log. Reads the current tip under
/// the same connection so concurrent appends don't see torn state.
/// Returns the (seq, entry_hash) of the newly-inserted row.
pub async fn append_entry(
    pool: &SqlitePool,
    envelope_hash_hex: &str,
    ts_ms: i64,
) -> Result<(i64, [u8; 32])> {
    // sqlx 0.8 sqlite pool serializes writes at the driver level; for
    // an extra safety margin we wrap in an explicit transaction. The
    // chain-head read + insert must be atomic w.r.t. other appenders.
    let mut tx = pool.begin().await.context("begin tx")?;

    let prev = sqlx::query("SELECT entry_hash FROM log_entries ORDER BY seq DESC LIMIT 1")
        .fetch_optional(&mut *tx)
        .await
        .context("read prev entry")?;
    let prev_hash: [u8; 32] = match prev {
        Some(row) => {
            let bytes: Vec<u8> = row.get(0);
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("prev_hash != 32 bytes (corruption)"))?
        }
        None => ZERO_HASH,
    };
    let entry_hash = compute_entry_hash(&prev_hash, envelope_hash_hex, ts_ms);

    let result = sqlx::query(
        "INSERT INTO log_entries (envelope_hash, prev_hash, entry_hash, ts_ms) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(envelope_hash_hex)
    .bind(prev_hash.to_vec())
    .bind(entry_hash.to_vec())
    .bind(ts_ms)
    .execute(&mut *tx)
    .await
    .context("insert log entry")?;

    let seq = result.last_insert_rowid();
    tx.commit().await.context("commit tx")?;
    Ok((seq, entry_hash))
}

/// Number of entries currently in the log (== latest `seq`).
pub async fn log_size(pool: &SqlitePool) -> Result<i64> {
    let row = sqlx::query("SELECT COUNT(*) FROM log_entries")
        .fetch_one(pool)
        .await
        .context("log size")?;
    Ok(row.get(0))
}

/// Current chain-head hash + size + timestamp. The "Signed Tree Head"
/// shape — sans signature, which lands in iter-2.
#[derive(Debug, Clone, PartialEq)]
pub struct UnsignedTreeHead {
    /// Number of entries.
    pub tree_size: i64,
    /// Latest entry's `entry_hash`, hex-encoded. For an empty log this
    /// is the all-zeros sentinel.
    pub root_hash_hex: String,
    /// Wall-clock when the tip was observed.
    pub timestamp_ms: i64,
}

/// Compute the current (unsigned) STH.
pub async fn current_sth(pool: &SqlitePool) -> Result<UnsignedTreeHead> {
    let row =
        sqlx::query("SELECT seq, entry_hash, ts_ms FROM log_entries ORDER BY seq DESC LIMIT 1")
            .fetch_optional(pool)
            .await
            .context("read tip")?;

    Ok(match row {
        Some(r) => UnsignedTreeHead {
            tree_size: r.get(0),
            root_hash_hex: hex::encode::<Vec<u8>>(r.get(1)),
            timestamp_ms: r.get(2),
        },
        None => UnsignedTreeHead {
            tree_size: 0,
            root_hash_hex: hex::encode(ZERO_HASH),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{connect_and_migrate, record_verification, VerificationRecord};

    async fn fresh_pool() -> SqlitePool {
        connect_and_migrate("sqlite::memory:").await.unwrap()
    }

    /// Insert a `verifications` parent row so the FK on `log_entries`
    /// is satisfied. Mirrors the production flow: the verify endpoint
    /// records the result, then appends a log entry pointing at it.
    async fn seed_parent(pool: &SqlitePool, envelope_hash: &str, ts_ms: i64) {
        record_verification(
            pool,
            &VerificationRecord {
                envelope_hash: envelope_hash.to_string(),
                submitted_at: ts_ms / 1000,
                payload_size_bytes: 1,
                ok: true,
                error_kind: None,
                report_json: None,
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn empty_log_returns_zero_size_and_genesis_hash() {
        let pool = fresh_pool().await;
        let size = log_size(&pool).await.unwrap();
        assert_eq!(size, 0);
        let sth = current_sth(&pool).await.unwrap();
        assert_eq!(sth.tree_size, 0);
        assert_eq!(sth.root_hash_hex, hex::encode(ZERO_HASH));
    }

    #[tokio::test]
    async fn first_append_chains_from_zero() {
        let pool = fresh_pool().await;
        let envelope_hash = "a".repeat(64);
        seed_parent(&pool, &envelope_hash, 1_000).await;
        let (seq, hash) = append_entry(&pool, &envelope_hash, 1_000).await.unwrap();
        assert_eq!(seq, 1);
        let expected = compute_entry_hash(&ZERO_HASH, &envelope_hash, 1_000);
        assert_eq!(hash, expected);
    }

    #[tokio::test]
    async fn second_append_chains_from_first() {
        let pool = fresh_pool().await;
        seed_parent(&pool, &"a".repeat(64), 1).await;
        seed_parent(&pool, &"b".repeat(64), 2).await;
        let h1 = append_entry(&pool, &"a".repeat(64), 1).await.unwrap().1;
        let (seq, h2) = append_entry(&pool, &"b".repeat(64), 2).await.unwrap();
        assert_eq!(seq, 2);
        let expected = compute_entry_hash(&h1, &"b".repeat(64), 2);
        assert_eq!(h2, expected);
    }

    #[tokio::test]
    async fn sth_reflects_tip_after_appends() {
        let pool = fresh_pool().await;
        seed_parent(&pool, &"a".repeat(64), 1).await;
        seed_parent(&pool, &"b".repeat(64), 2).await;
        seed_parent(&pool, &"c".repeat(64), 3).await;
        append_entry(&pool, &"a".repeat(64), 1).await.unwrap();
        append_entry(&pool, &"b".repeat(64), 2).await.unwrap();
        let (_, h3) = append_entry(&pool, &"c".repeat(64), 3).await.unwrap();

        let sth = current_sth(&pool).await.unwrap();
        assert_eq!(sth.tree_size, 3);
        assert_eq!(sth.root_hash_hex, hex::encode(h3));
        assert_eq!(sth.timestamp_ms, 3);
    }

    #[tokio::test]
    async fn chain_replay_verifies_log_integrity() {
        // Replay all entries forward; the computed chain head must
        // match the stored tip hash. This is what a third-party
        // auditor will run against the public log.
        let pool = fresh_pool().await;
        let entries = [
            ("a".repeat(64), 100),
            ("b".repeat(64), 200),
            ("c".repeat(64), 300),
            ("d".repeat(64), 400),
        ];
        for (eh, ts) in &entries {
            seed_parent(&pool, eh, *ts).await;
            append_entry(&pool, eh, *ts).await.unwrap();
        }

        let mut chain = ZERO_HASH;
        for (eh, ts) in &entries {
            chain = compute_entry_hash(&chain, eh, *ts);
        }

        let sth = current_sth(&pool).await.unwrap();
        assert_eq!(sth.root_hash_hex, hex::encode(chain));
        assert_eq!(sth.tree_size, entries.len() as i64);
    }

    #[tokio::test]
    async fn distinct_envelope_hashes_yield_distinct_chain_tips() {
        let p1 = fresh_pool().await;
        let p2 = fresh_pool().await;
        seed_parent(&p1, &"a".repeat(64), 1).await;
        seed_parent(&p2, &"b".repeat(64), 1).await;
        append_entry(&p1, &"a".repeat(64), 1).await.unwrap();
        append_entry(&p2, &"b".repeat(64), 1).await.unwrap();
        let s1 = current_sth(&p1).await.unwrap();
        let s2 = current_sth(&p2).await.unwrap();
        assert_ne!(s1.root_hash_hex, s2.root_hash_hex);
    }

    #[tokio::test]
    async fn append_with_missing_parent_fails_loud() {
        let pool = fresh_pool().await;
        // No seed_parent — the FK should reject the append.
        let result = append_entry(&pool, &"z".repeat(64), 999).await;
        assert!(
            result.is_err(),
            "FK to verifications must enforce a real parent verification"
        );
    }
}
