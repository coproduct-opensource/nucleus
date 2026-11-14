//! A database written by the sqlx-backed release opens under this driver,
//! with nothing re-run and nothing lost.
//!
//! `tests/fixtures/sqlx-0.9-created.db` was written by this crate at
//! `7f511159f` (sqlx 0.9.0, libsqlite3-sys 0.30.1) through its own public
//! functions: `connect_and_migrate_path`, then three `record_verification`
//! calls (`a`…, `b`… succeeded, `c`… failed with `BadSignature`) and two
//! `log_append_entry` calls (`a`… at 1_700_000_000_000 ms, `b`… at
//! 1_700_000_001_000 ms), then `pool.close()`, which checkpointed the WAL into
//! the one file. Its SHA-256 is
//! `d309c4d3e23f52a373bfb1fead4abe5bb2ccbdc900bcc61c168fd9d799d79354`.
//!
//! The checksums and descriptions in its `_sqlx_migrations` are sqlx's own, so
//! they are the oracle for "the migrations are identical": this code computes
//! its own and must agree, or it refuses to open the file.

use super::*;
use crate::log::{ZERO_HASH, compute_entry_hash, current_sth, log_size};

const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/sqlx-0.9-created.db");

/// `(version, description, success, checksum, execution_time, installed_on)`
type MigrationRow = (i64, String, bool, Vec<u8>, i64, String);

async fn bookkeeping(db: &Db) -> Vec<MigrationRow> {
    db.call(|conn| {
        let mut stmt = conn.prepare(
            "SELECT version, description, success, checksum, execution_time, installed_on \
             FROM _sqlx_migrations ORDER BY version",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    })
    .await
    .unwrap()
}

fn fixture_copy() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verifier.db");
    std::fs::write(&path, FIXTURE).unwrap();
    (dir, path)
}

#[tokio::test]
async fn sqlx_recorded_the_same_migrations_this_build_embeds() {
    let (_dir, path) = fixture_copy();
    let db = connect_and_migrate_path(&path).await.unwrap();
    let rows = bookkeeping(&db).await;
    assert_eq!(rows.len(), MIGRATIONS.len());
    for (row, migration) in rows.iter().zip(MIGRATIONS) {
        let (version, description, success, checksum, _, _) = row;
        assert_eq!(*version, migration.version);
        assert_eq!(description, migration.description);
        assert!(success);
        assert_eq!(
            checksum.as_slice(),
            Sha384::digest(migration.sql).as_slice(),
            "sqlx's stored checksum for {version} differs from this build's"
        );
    }
}

#[tokio::test]
async fn opening_a_sqlx_database_runs_no_migration() {
    let (_dir, path) = fixture_copy();
    let first = bookkeeping(&connect_and_migrate_path(&path).await.unwrap()).await;
    let second = bookkeeping(&connect_and_migrate_path(&path).await.unwrap()).await;
    // sqlx wrote a real execution_time and installed_on; a re-run would have
    // replaced the row (or failed on CREATE TABLE before reaching it).
    assert_eq!(first, second);
    for (version, _, _, _, execution_time, _) in &first {
        assert!(
            *execution_time > 0,
            "migration {version} kept sqlx's timing"
        );
    }
}

#[tokio::test]
async fn every_row_sqlx_wrote_reads_back() {
    let (_dir, path) = fixture_copy();
    let db = connect_and_migrate_path(&path).await.unwrap();

    let a = fetch_verification(&db, &"a".repeat(64))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        a,
        VerificationRecord {
            envelope_hash: "a".repeat(64),
            submitted_at: 1_700_000_000,
            payload_size_bytes: 100,
            ok: true,
            error_kind: None,
            report_json: Some(r#"{"edge_count":1}"#.to_string()),
        }
    );
    let c = fetch_verification(&db, &"c".repeat(64))
        .await
        .unwrap()
        .unwrap();
    assert!(!c.ok);
    assert_eq!(c.error_kind.as_deref(), Some("BadSignature"));
    assert!(c.report_json.is_none());

    // The chain sqlx wrote is the chain this code recomputes.
    let h1 = compute_entry_hash(&ZERO_HASH, &"a".repeat(64), 1_700_000_000_000);
    let h2 = compute_entry_hash(&h1, &"b".repeat(64), 1_700_000_001_000);
    assert_eq!(log_size(&db).await.unwrap(), 2);
    let sth = current_sth(&db).await.unwrap();
    assert_eq!(sth.tree_size, 2);
    assert_eq!(sth.root_hash_hex, hex::encode(h2));
    assert_eq!(sth.timestamp_ms, 1_700_000_001_000);

    let merkle = crate::merkle::MerkleLog::from_persisted_entries(&db)
        .await
        .unwrap();
    assert_eq!(merkle.size(), 2);
}

#[tokio::test]
async fn the_log_continues_from_sqlxs_tip() {
    let (_dir, path) = fixture_copy();
    let db = connect_and_migrate_path(&path).await.unwrap();
    let d = "d".repeat(64);
    record_verification(
        &db,
        &VerificationRecord {
            envelope_hash: d.clone(),
            submitted_at: 1_700_000_003,
            payload_size_bytes: 1,
            ok: true,
            error_kind: None,
            report_json: None,
        },
    )
    .await
    .unwrap();
    let (seq, hash) = crate::log::append_entry(&db, &d, 1_700_000_003_000)
        .await
        .unwrap();
    assert_eq!(seq, 3);
    let tip = hex::decode(current_sth(&db).await.unwrap().root_hash_hex).unwrap();
    assert_eq!(tip, hash);
    let h1 = compute_entry_hash(&ZERO_HASH, &"a".repeat(64), 1_700_000_000_000);
    let h2 = compute_entry_hash(&h1, &"b".repeat(64), 1_700_000_001_000);
    assert_eq!(hash, compute_entry_hash(&h2, &d, 1_700_000_003_000));
}
