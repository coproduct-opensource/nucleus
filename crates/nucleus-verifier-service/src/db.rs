//! SQLite persistence layer for the verifier-service.
//!
//! Optional — when [`AppState::db`](crate::app::AppState) is `None`
//! the service runs in legacy stateless mode and no records are
//! written. When `Some(SqlitePool)`, every verification is recorded
//! and addressable by envelope hash via the
//! `GET /v1/bundles/{hash}/verify` endpoint (task #68 wires that).
//!
//! # Why SQLite (not Postgres) in v1
//!
//! - Fly.io single-volume deployment is the v1 ship target; SQLite
//!   removes one moving part vs. running a Postgres sidecar.
//! - All access is single-writer (verifier-service) + many-reader (the
//!   public verify endpoint); SQLite's WAL mode handles this well.
//! - Migrations are checked-in plain `.sql` files; no DB ops required.
//! - Multi-region read replicas can come later via litestream / LiteFS;
//!   no schema change needed to swap the storage substrate.

use std::path::Path;

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

/// Default pool size — sized to comfortably outrun the
/// `MAX_CONCURRENT_REQUESTS` ceiling (256) at any given verifier
/// thread count.
const DEFAULT_POOL_SIZE: u32 = 8;

/// Construct + warm the SqlitePool. Creates the file if missing,
/// enables WAL for many-reader/single-writer concurrency, and runs
/// embedded migrations.
///
/// `db_url` accepts the standard sqlx forms:
/// - `sqlite::memory:` (tests)
/// - `sqlite:/data/verifier.db` (Fly.io volume mount)
/// - any path-shaped string is treated as `sqlite:<path>`
pub async fn connect_and_migrate(db_url: &str) -> Result<SqlitePool> {
    let normalized = if db_url.starts_with("sqlite:") {
        db_url.to_string()
    } else {
        format!("sqlite:{db_url}")
    };

    let options: SqliteConnectOptions = normalized
        .parse::<SqliteConnectOptions>()
        .with_context(|| format!("invalid sqlite URL: {normalized}"))?
        // WAL mode = readers don't block the writer. Critical for a
        // service that's mostly verify (write) but exposes a public
        // hash-lookup endpoint (read).
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        // NORMAL synchronous is the WAL-mode-recommended setting —
        // FULL is overkill (no extra durability over WAL checkpoints)
        // and OFF risks corruption on power loss.
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        // Auto-create the DB file on first connect so the Fly.io
        // initial deploy doesn't need a bootstrap step.
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(DEFAULT_POOL_SIZE)
        .connect_with(options)
        .await
        .context("connect_with(SqliteConnectOptions) failed")?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("running embedded migrations failed")?;

    Ok(pool)
}

/// Helper variant for tests/CI that takes a raw path.
pub async fn connect_and_migrate_path(path: &Path) -> Result<SqlitePool> {
    let url = format!("sqlite:{}", path.display());
    connect_and_migrate(&url).await
}

/// A persisted verification record. Mirrors the `verifications` table.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationRecord {
    /// SHA-256 hex of `nucleus_envelope::canonical_bundle_hash`
    /// — primary key + URL component for the lookup endpoint.
    pub envelope_hash: String,
    /// Unix seconds at submission.
    pub submitted_at: i64,
    /// Size of the bundle JSON the verifier received (for telemetry
    /// + retention sweeper budget).
    pub payload_size_bytes: i64,
    /// `true` when verification succeeded; `false` on any failure.
    pub ok: bool,
    /// Discriminant of `VerifyBundleError` when `!ok`. Stable across
    /// release versions of `nucleus-envelope`.
    pub error_kind: Option<String>,
    /// Full `VerificationReport` JSON on success; `None` on failure.
    pub report_json: Option<String>,
}

/// Idempotent insert. Re-submitting the same `envelope_hash` is a
/// no-op (we treat it as "we already verified that bundle"; the
/// stored report wins).
pub async fn record_verification(pool: &SqlitePool, rec: &VerificationRecord) -> Result<()> {
    sqlx::query(
        "INSERT INTO verifications \
            (envelope_hash, submitted_at, payload_size_bytes, ok, error_kind, report_json) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT(envelope_hash) DO NOTHING",
    )
    .bind(&rec.envelope_hash)
    .bind(rec.submitted_at)
    .bind(rec.payload_size_bytes)
    .bind(if rec.ok { 1i64 } else { 0i64 })
    .bind(&rec.error_kind)
    .bind(&rec.report_json)
    .execute(pool)
    .await
    .context("INSERT INTO verifications failed")?;
    Ok(())
}

/// Look up a previously-recorded verification by envelope hash.
pub async fn fetch_verification(
    pool: &SqlitePool,
    envelope_hash: &str,
) -> Result<Option<VerificationRecord>> {
    let row = sqlx::query(
        "SELECT envelope_hash, submitted_at, payload_size_bytes, ok, error_kind, report_json \
         FROM verifications WHERE envelope_hash = ?",
    )
    .bind(envelope_hash)
    .fetch_optional(pool)
    .await
    .context("SELECT FROM verifications failed")?;

    Ok(row.map(|r| VerificationRecord {
        envelope_hash: r.get(0),
        submitted_at: r.get(1),
        payload_size_bytes: r.get(2),
        ok: r.get::<i64, _>(3) != 0,
        error_kind: r.get(4),
        report_json: r.get(5),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fresh_pool() -> SqlitePool {
        // Each in-memory test gets its own DB to avoid cross-test bleed.
        connect_and_migrate("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn migrations_run_on_fresh_db() {
        let pool = fresh_pool().await;
        // Schema migration created the table; a select on it must
        // succeed (even with zero rows).
        let r = sqlx::query("SELECT COUNT(*) FROM verifications")
            .fetch_one(&pool)
            .await
            .unwrap();
        let n: i64 = r.get(0);
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn round_trip_success_record() {
        let pool = fresh_pool().await;
        let rec = VerificationRecord {
            envelope_hash: "a".repeat(64),
            submitted_at: 1_700_000_000,
            payload_size_bytes: 4096,
            ok: true,
            error_kind: None,
            report_json: Some(r#"{"trust_mode":"jwks","edge_count":3}"#.to_string()),
        };
        record_verification(&pool, &rec).await.unwrap();
        let back = fetch_verification(&pool, &rec.envelope_hash)
            .await
            .unwrap()
            .expect("just inserted");
        assert_eq!(back, rec);
    }

    #[tokio::test]
    async fn round_trip_failure_record() {
        let pool = fresh_pool().await;
        let rec = VerificationRecord {
            envelope_hash: "b".repeat(64),
            submitted_at: 1_700_000_001,
            payload_size_bytes: 512,
            ok: false,
            error_kind: Some("BadSignature".to_string()),
            report_json: None,
        };
        record_verification(&pool, &rec).await.unwrap();
        let back = fetch_verification(&pool, &rec.envelope_hash)
            .await
            .unwrap()
            .unwrap();
        assert!(!back.ok);
        assert_eq!(back.error_kind.as_deref(), Some("BadSignature"));
        assert!(back.report_json.is_none());
    }

    #[tokio::test]
    async fn fetch_returns_none_for_unknown_hash() {
        let pool = fresh_pool().await;
        let got = fetch_verification(&pool, &"c".repeat(64)).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn idempotent_insert_does_not_overwrite() {
        let pool = fresh_pool().await;
        let r1 = VerificationRecord {
            envelope_hash: "d".repeat(64),
            submitted_at: 1,
            payload_size_bytes: 100,
            ok: true,
            error_kind: None,
            report_json: Some("first".to_string()),
        };
        let r2 = VerificationRecord {
            envelope_hash: "d".repeat(64), // same hash
            submitted_at: 2,
            payload_size_bytes: 200,
            ok: false,
            error_kind: Some("ShouldNotOverwrite".to_string()),
            report_json: Some("second".to_string()),
        };
        record_verification(&pool, &r1).await.unwrap();
        record_verification(&pool, &r2).await.unwrap();
        let back = fetch_verification(&pool, &r1.envelope_hash)
            .await
            .unwrap()
            .unwrap();
        // First-write-wins: r2's fields must NOT overwrite r1's.
        assert_eq!(back, r1);
    }
}
