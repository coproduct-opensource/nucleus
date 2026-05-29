//! Background retention sweeper for the `verifications` table.
//!
//! Once an hour (configurable), DELETEs rows older than the operator-
//! configured retention window. Runs as a spawned tokio task whose
//! lifetime is bound by a [`tokio_util::sync::CancellationToken`] —
//! main.rs cancels at shutdown so the sweeper finishes its current
//! sweep + releases the DB connection cleanly.
//!
//! # Retention semantics (v1)
//!
//! v1 of the verifier service does NOT archive raw bundle bytes; the
//! `verifications` table holds only `(envelope_hash, submitted_at,
//! payload_size_bytes, ok, error_kind, report_json)`. The sweeper
//! therefore operates by deleting whole rows after the retention
//! window expires. The data lost is the report JSON + the
//! ok/error_kind discriminant; the bundle hash itself remains in the
//! transparency log's `log_entries` table (which is append-only and
//! never swept).
//!
//! When v2 adds an opt-in `payload_archive` BLOB column, this module
//! gains a separate `retention_archive_days` knob that NULLs the BLOB
//! after a shorter window while keeping the row.
//!
//! # Default posture
//!
//! When retention is unset (`None`) the sweeper runs but does nothing
//! — rows stay forever. Set `--retention-days N` to enable actual
//! deletion. The sweeper still ticks (logs the configured state at
//! each tick) so operators can observe the configuration is live.

use std::time::Duration;

use anyhow::Result;
use sqlx::SqlitePool;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
use sqlx::Row;

/// Default sweep cadence. Operators tune via the (currently
/// unexposed) `RETENTION_SWEEP_INTERVAL_SECS` env if needed; the
/// const exists so the threat-model doc + tests can reference it.
pub const DEFAULT_SWEEP_INTERVAL_SECS: u64 = 3600;

/// Result of one sweep tick.
#[derive(Debug, PartialEq, Eq)]
pub struct SweepReport {
    /// Rows deleted in this sweep.
    pub rows_deleted: u64,
    /// Cutoff timestamp (unix seconds): rows with `submitted_at`
    /// strictly less than this were deleted.
    pub cutoff_secs: i64,
}

/// Compute the unix-seconds cutoff for a given retention window.
/// Clamped to ≥ 0 so a misconfiguration (huge retention vs. small
/// `now`) never asks the DB to delete using a negative cutoff
/// (which would still be deterministic, just confusing in logs).
fn compute_cutoff(now_secs: i64, retention_secs: i64) -> i64 {
    now_secs.saturating_sub(retention_secs).max(0)
}

/// Run one sweep against the pool. Pure async fn so tests can drive
/// the cutoff math without spawning a background task.
pub async fn sweep_once(
    pool: &SqlitePool,
    retention_secs: i64,
    now_secs: i64,
) -> Result<SweepReport> {
    let cutoff = compute_cutoff(now_secs, retention_secs);
    let result = sqlx::query("DELETE FROM verifications WHERE submitted_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await?;
    let rows_deleted = result.rows_affected();

    if rows_deleted > 0 {
        tracing::info!(
            rows_deleted,
            cutoff_secs = cutoff,
            "retention sweep deleted rows past retention window"
        );
    }
    Ok(SweepReport {
        rows_deleted,
        cutoff_secs: cutoff,
    })
}

/// Spawn the sweeper as a background tokio task. The task ticks on
/// `interval_secs`; each tick calls [`sweep_once`] with the current
/// wall-clock + the configured retention. Cancellation token causes
/// the task to drop out cleanly (no `tokio::select!` racing the
/// timer; just a polled cancel check between ticks).
pub fn spawn(
    pool: SqlitePool,
    retention_secs: Option<i64>,
    interval_secs: u64,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(interval_secs));
        // First tick fires immediately; skip it so startup logs are
        // clean and the first action is at +interval.
        ticker.tick().await;
        tracing::info!(
            interval_secs,
            retention_secs = ?retention_secs,
            "retention sweeper spawned"
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("retention sweeper shutdown signal received");
                    return;
                }
                _ = ticker.tick() => {
                    match retention_secs {
                        Some(secs) => {
                            let now = chrono::Utc::now().timestamp();
                            if let Err(e) = sweep_once(&pool, secs, now).await {
                                tracing::warn!(error = %e, "retention sweep failed");
                            }
                        }
                        None => {
                            tracing::debug!("retention disabled; sweep tick is no-op");
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{connect_and_migrate, record_verification, VerificationRecord};

    async fn fresh_pool() -> SqlitePool {
        connect_and_migrate("sqlite::memory:").await.unwrap()
    }

    async fn insert(pool: &SqlitePool, hash: &str, submitted_at: i64) {
        record_verification(
            pool,
            &VerificationRecord {
                envelope_hash: hash.to_string(),
                submitted_at,
                payload_size_bytes: 100,
                ok: true,
                error_kind: None,
                report_json: Some("{}".to_string()),
            },
        )
        .await
        .unwrap();
    }

    async fn row_count(pool: &SqlitePool) -> i64 {
        sqlx::query("SELECT COUNT(*) FROM verifications")
            .fetch_one(pool)
            .await
            .unwrap()
            .try_get::<i64, _>(0)
            .unwrap()
    }

    #[test]
    fn cutoff_math_is_now_minus_retention() {
        assert_eq!(compute_cutoff(1_000, 200), 800);
        assert_eq!(compute_cutoff(100, 1_000), 0); // saturating
    }

    #[tokio::test]
    async fn sweep_keeps_fresh_rows_deletes_old() {
        let pool = fresh_pool().await;
        let now = 1_700_000_000;
        // Fresh row (just inserted now).
        insert(&pool, &"a".repeat(64), now).await;
        // Old row (older than retention).
        insert(&pool, &"b".repeat(64), now - 1_000_000).await;
        assert_eq!(row_count(&pool).await, 2);

        // Retention = 100_000 seconds; cutoff = now - 100_000.
        let report = sweep_once(&pool, 100_000, now).await.unwrap();
        assert_eq!(report.rows_deleted, 1);
        assert_eq!(report.cutoff_secs, now - 100_000);
        assert_eq!(row_count(&pool).await, 1);
    }

    #[tokio::test]
    async fn sweep_with_huge_retention_is_noop() {
        let pool = fresh_pool().await;
        let now = 1_700_000_000;
        insert(&pool, &"a".repeat(64), now - 100).await;
        let report = sweep_once(&pool, 1_000_000_000, now).await.unwrap();
        assert_eq!(report.rows_deleted, 0);
        assert_eq!(row_count(&pool).await, 1);
    }

    #[tokio::test]
    async fn sweep_on_empty_table_is_noop() {
        let pool = fresh_pool().await;
        let report = sweep_once(&pool, 1, 1_000).await.unwrap();
        assert_eq!(report.rows_deleted, 0);
    }

    #[tokio::test]
    async fn cancel_returns_quickly() {
        let pool = fresh_pool().await;
        let cancel = CancellationToken::new();
        let h = spawn(pool, None, 3600, cancel.clone());
        // Should NOT immediately tick (we skip first tick).
        cancel.cancel();
        // Background task observes cancellation between ticks; since
        // first tick was skipped and we cancelled before the second,
        // it should resolve quickly.
        let result = tokio::time::timeout(Duration::from_secs(2), h).await;
        assert!(result.is_ok(), "spawned task must exit within 2s on cancel");
    }
}
