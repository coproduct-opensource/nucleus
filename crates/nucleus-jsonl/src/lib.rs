//! Append one record to a line-oriented log, as ONE write.
//!
//! # Why this crate exists
//!
//! Four logs in this workspace wrote each record as two writes — the line, then
//! `"\n"` — through tokio's file, where each write is its own blocking operation:
//! the node's collected mediation receipts, its collected Article 12 records, its
//! pod lifecycle audit, and the tool-proxy's hash-chained audit log. Every one has
//! concurrent writers (receipts and records arrive on several connections, tool
//! calls are served in parallel, cancel races the reaper), and under concurrency
//! every one tore: a line cut short, another spliced into it, stray newlines. The
//! logs are evidence, and a torn line is one the verifier cannot read past — a
//! corruption the node produced itself.
//!
//! Each was fixed by making the record one write on a file opened `O_APPEND`, which
//! positions and writes atomically. A record whose acceptance is acknowledged is
//! also synced, and the acknowledgement is built from the [`Durable`] proof that
//! only [`append_line_synced`] returns. Four copies of that would be four places to get
//! it wrong again, so it is here once, and `clippy.toml` refuses
//! `OpenOptions::append` everywhere else (ADR 0007 G-1: one decider per fact).
//!
//! # What this does not promise
//!
//! - **Order between writers.** Two records appended concurrently land in some
//!   order. A log whose lines are chained (each naming the previous) must serialise
//!   "extend the chain" and "append" under one lock itself — the tool-proxy's audit
//!   log does.
//! - **A short write.** On ENOSPC a write can land partially. That is returned as an
//!   error, which every caller treats as "not recorded".

#![forbid(unsafe_code)]
// Declared panic-free for the shipped build (the scorecard's `tot` family): a
// record log's append must fail as an `Err`, never take the writer down.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

use std::io::Write;
use std::path::Path;
#[cfg(feature = "async")]
use std::path::PathBuf;

/// Proof that a record was appended AND synced to disk.
///
/// Only [`append_line_synced`] makes one: the field is private (ADR 0007 C-1), and it
/// is neither `Clone` nor `Copy`, so one proof acknowledges one record. A collector
/// that tells a peer "your record is kept" builds that reply from this value, so
/// acknowledging a record that was never appended — or only reached the page cache,
/// which a host crash loses — does not compile.
///
/// ```compile_fail
/// // Outside this crate a `Durable` cannot be made without appending.
/// let forged = nucleus_jsonl::Durable { _sealed: () };
/// ```
#[must_use = "a Durable is the proof an acknowledgement is built from; dropping it acknowledges nothing"]
#[derive(Debug)]
pub struct Durable {
    _sealed: (),
}

fn append(path: &Path, line: &str, sync: bool) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let trimmed = line.trim_end().as_bytes();
    let mut record = Vec::with_capacity(trimmed.len().saturating_add(1));
    record.extend_from_slice(trimmed);
    record.push(b'\n');
    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0007 G-1: this is the one place a record log is opened for append"
    )]
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(&record)?;
    if sync {
        file.sync_data()?;
    }
    Ok(())
}

/// Append `line` (trailing whitespace trimmed) and one newline to `path` as a single
/// `O_APPEND` write, then `fdatasync`. For records whose acceptance is acknowledged.
///
/// # Errors
/// If the directory or file cannot be created, or the write or sync fails or is
/// short. No [`Durable`] is returned, so nothing can be acknowledged.
pub fn append_line_synced(path: &Path, line: &str) -> std::io::Result<Durable> {
    append(path, line, true)?;
    Ok(Durable { _sealed: () })
}

/// As [`append_line_synced`], without the sync: the record is in the page cache and
/// a host crash loses it. Returns no [`Durable`], so it cannot back an
/// acknowledgement.
///
/// # Errors
/// If the directory or file cannot be created, or the write fails or is short.
pub fn append_line_unsynced(path: &Path, line: &str) -> std::io::Result<()> {
    append(path, line, false)
}

/// [`append_line_synced`] on tokio's blocking pool.
///
/// # Errors
/// As [`append_line_synced`], or if the blocking task panicked.
#[cfg(feature = "async")]
pub async fn append_line_synced_async(path: PathBuf, line: String) -> std::io::Result<Durable> {
    tokio::task::spawn_blocking(move || append_line_synced(&path, &line))
        .await
        .map_err(std::io::Error::other)?
}

/// [`append_line_unsynced`] on tokio's blocking pool.
///
/// # Errors
/// As [`append_line_unsynced`], or if the blocking task panicked.
#[cfg(feature = "async")]
pub async fn append_line_unsynced_async(path: PathBuf, line: String) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || append_line_unsynced(&path, &line))
        .await
        .map_err(std::io::Error::other)?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the crate exists for: many concurrent appends, every line whole
    /// and present exactly once.
    #[test]
    fn concurrent_appends_never_tear_a_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("log.jsonl");
        let threads: Vec<_> = (0..128u64)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let line = format!(r#"{{"n":{t},"pad":"{}"}}"#, "x".repeat(4096));
                    append_line_unsynced(&path, &line).unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut ns: Vec<u64> = raw
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .unwrap_or_else(|_| panic!("a torn line: {}", &l[..l.len().min(40)]))["n"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        ns.sort_unstable();
        assert_eq!(ns, (0..128).collect::<Vec<u64>>());
    }

    #[test]
    fn a_trailing_newline_is_not_doubled_and_the_file_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        let _kept = append_line_synced(&path, "{\"a\":1}\n").unwrap();
        let _kept = append_line_synced(&path, "{\"a\":2}").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"a\":1}\n{\"a\":2}\n"
        );
    }

    #[test]
    fn an_unwritable_path_is_an_error_not_a_silent_drop() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the file should be.
        let path = dir.path().join("log.jsonl");
        std::fs::create_dir(&path).unwrap();
        assert!(append_line_unsynced(&path, "{}").is_err());
        assert!(append_line_synced(&path, "{}").is_err());
    }
}
