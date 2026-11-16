# nucleus-verifier-service: what its database and log guarantee

**Written 2026-11-14**, before the change that moves the service's SQLite driver from sqlx 0.9 to
rusqlite 0.42 (RUSTSEC-2026-0459). Driver changes must keep the guarantees below. The section on
the driver change says how each one was checked.

Persistence is optional. Without `--db` / `NUCLEUS_VERIFIER_DB` the service writes nothing, and
the log and lookup endpoints answer 503. Everything below applies only when `--db` is set.

## The state

One SQLite file, `/data/verifier.db` in the shipped `fly.toml`, holding two tables. The schema is
`crates/nucleus-verifier-service/migrations/`.

- **`verifications`**: one row per distinct `envelope_hash`, for successful and failed
  verifications alike.
- **`log_entries`**: the transparency log. It has one row per *successful* verification, chained
  by hash. `envelope_hash` is a foreign key into `verifications`.

The service also keeps an in-memory RFC 9162 Merkle tree over `log_entries.entry_hash` (`merkle.rs`).
It is rebuilt from the table at startup.

## Guarantees

**G1. First write wins per bundle.** `record_verification` inserts with
`ON CONFLICT(envelope_hash) DO NOTHING`. A bundle re-submitted later, even one that now verifies
differently, does not change the stored outcome. `GET /v1/bundles/{hash}/verify` returns the first
outcome. Test: `db::tests::idempotent_insert_does_not_overwrite`.

**G2. Persistence never changes a verdict.** A database error during `POST /v1/verify` is logged,
and the response is the verifier's (`routes.rs`, "Best-effort persistence"). So a 200 does not
mean the result was stored.

**G3. Only successful verifications enter the log.** A failed bundle is recorded in
`verifications` and never appended to `log_entries`.

**G4. The log is a hash chain from a fixed genesis.** Each entry is defined as:

    entry_hash = SHA-256(prev_hash || envelope_hash_hex_bytes || ts_ms as 8 big-endian bytes)

The first entry's `prev_hash` is 32 zero bytes. `compute_entry_hash` is the only definition.
Anyone holding the rows can replay the chain to the published tip.
Test: `log::tests::chain_replay_verifies_log_integrity`.

**G5. Reading the tip and appending are one transaction.** `append_entry` reads the previous
`entry_hash` and inserts the new row inside a single transaction, so two appends cannot chain from
the same tip. Under sqlx that was a transaction on one pooled connection. Under rusqlite it is a
transaction on the only connection, behind a mutex.

**G6. `seq` is never reused.** The column is `INTEGER PRIMARY KEY AUTOINCREMENT`, so a deleted row's
number is not handed out again. Nothing deletes from `log_entries`.

**G7. A log entry names a real verification.** `PRAGMA foreign_keys=ON` is set on every
connection; sqlx set it by default and the rusqlite code sets it explicitly. An append without a
`verifications` row fails. Test: `log::tests::append_with_missing_parent_fails_loud`.

**G8. Migrations run once, and an edited migration is refused.** `_sqlx_migrations` records each
applied migration with a SHA-384 checksum of its script. Opening a database refuses three cases:
a migration recorded as unfinished, a migration recorded but not embedded in the build, and a
recorded checksum that differs from the embedded script's. That is sqlx's rule, and the rusqlite
code keeps it. Test: `db::tests::an_edited_migration_is_refused`.

## What it does not guarantee

- **Durability across power loss.** The connection runs `journal_mode=WAL` with
  `synchronous=NORMAL`. A committed transaction survives a process crash, but it can be lost on
  power loss or an OS crash before the next checkpoint. A signed tree head already served for
  such an entry would then name a tip the file no longer has.
- **Tamper evidence against the file's owner.** Whoever can write `/data/verifier.db` can rewrite
  the chain and recompute every hash. The log is only as tamper-evident as what is published
  outside the file: signed tree heads (`--signing-key`) and peer witness cosignatures.
- **The Merkle tree's leaf order under concurrent appends.** `routes.rs` pushes a leaf into the
  in-memory tree *after* `append_entry` returns, in a separate step. If two verify requests append
  concurrently, they can push in the opposite order to their `seq`. Proofs served before the next
  restart are then over that order, and after a restart (rebuilt by `seq`) they are not. This is
  read from the code, not measured, and it is the same under both drivers.
- **Retention on logged rows.** `retention::sweep_once` runs
  `DELETE FROM verifications WHERE submitted_at < ?`. Because of G7, that statement fails with
  `FOREIGN KEY constraint failed` whenever any row it would delete is referenced by `log_entries`.
  That is every successful verification. The statement is atomic, so a sweep that reaches one
  deletes nothing and logs a warning. The module's own doc says rows are deleted while the log
  keeps the hash. That is not what happens. Measured 2026-11-13 with a throwaway test on the
  rusqlite branch (`FOREIGN KEY constraint failed: Error code 787`). The pragma and schema are the
  same as under sqlx. Not changed here: fixing it means deciding whether the FK or the sweep's
  scope gives way.

## The driver change (sqlx 0.9 → rusqlite 0.42)

**Why.** RUSTSEC-2026-0459: every bundled SQLite before 3.54.0 can return uninitialized page-cache
memory when a database is opened beside a `-wal` file with a different page size. `sqlx-sqlite`
0.9.0 is the newest sqlx release, pre-releases included, and it requires
`libsqlite3-sys >=0.30.1, <0.38.0`. The patched line starts at 0.39. rusqlite 0.42 uses
`libsqlite3-sys` 0.40 (SQLite 3.54+).

**What stays the same.**

- The schema and migration files are byte-identical.
- The bookkeeping table: same name (`_sqlx_migrations`), same columns, the same SHA-384 checksum,
  and the same description (the file name after the version, `_` read as a space).
- The pragmas sqlx set: WAL, `synchronous=NORMAL`, `foreign_keys=ON`, and a 5 s busy timeout.
- The accepted `--db` forms: `sqlite::memory:`, `sqlite:<path>`, `sqlite://<path>`, and a bare path.

**What changes.**

- **One connection.** sqlx used a pool of up to 8 connections; rusqlite uses one, behind a mutex,
  and runs each call on tokio's blocking pool. Reads no longer run in parallel with each other.
  Every statement here touches one row, except the Merkle rebuild at startup, which reads all of
  `log_entries` once.
- **`--db` query parameters are refused.** sqlx accepted `?mode=…` and similar; the rusqlite code
  refuses them rather than making them part of a file name.
- **The migration list comes from `build.rs`.** It is derived from `migrations/` instead of
  `sqlx::migrate!`.

**How compatibility was checked.**

- **A database sqlx wrote, opened by the new code.** The fixture
  `crates/nucleus-verifier-service/tests/fixtures/sqlx-0.9-created.db` was written by the crate at
  `7f511159f` (sqlx), through its public functions. It holds three verifications and two log
  entries. The tests are in `src/db_sqlx_compat_tests.rs`:
  - sqlx's stored checksums and descriptions equal the new build's;
  - opening the file twice leaves `_sqlx_migrations` unchanged, including sqlx's `installed_on` and
    `execution_time`, so nothing re-ran;
  - every row reads back, and the stored tip equals the chain recomputed from G4;
  - the next append continues from sqlx's tip as `seq` 3.
- **The checksum check can fail.** With the checksum computed over `sql.trim_end()` instead of the
  script, all four tests fail with `checksum mismatch`. Restored, they pass.
- **Both binaries on one file.** `main`'s binary (sqlx) and the branch's binary (rusqlite) were
  started in turn against one `--db` file, in both orders. Each served `GET /v1/log/size`. A re-run
  migration would have failed startup on `CREATE TABLE`.
