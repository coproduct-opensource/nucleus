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
//! positions and writes atomically. Four copies of that would be four places to get
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

use std::io::Write;
use std::path::Path;
#[cfg(feature = "async")]
use std::path::PathBuf;

/// Whether an append is synced to disk before it returns.
///
/// No default (ADR 0007 B-1): a record the caller acknowledges to someone — a
/// receipt a pod was told was collected — must be `Synced`, and the choice is made
/// at each call site where that is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// `fdatasync` before returning. For records whose acceptance is acknowledged.
    Synced,
    /// Written to the page cache only. Lost by a host crash.
    PageCache,
}

/// Append `line` (trailing whitespace trimmed) and one newline to `path` as a single
/// `O_APPEND` write, creating the file and its parent directory if needed.
///
/// # Errors
/// If the directory or file cannot be created, the write fails or is short, or the
/// sync fails. The record must then be treated as not written.
pub fn append_line(path: &Path, line: &str, durability: Durability) -> std::io::Result<()> {
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
    match durability {
        Durability::Synced => file.sync_data(),
        Durability::PageCache => Ok(()),
    }
}

/// [`append_line`] on tokio's blocking pool.
#[cfg(feature = "async")]
///
/// # Errors
/// As [`append_line`], or if the blocking task panicked.
pub async fn append_line_async(
    path: PathBuf,
    line: String,
    durability: Durability,
) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || append_line(&path, &line, durability))
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
                    append_line(&path, &line, Durability::PageCache).unwrap();
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
        append_line(&path, "{\"a\":1}\n", Durability::Synced).unwrap();
        append_line(&path, "{\"a\":2}", Durability::Synced).unwrap();
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
        assert!(append_line(&path, "{}", Durability::PageCache).is_err());
    }
}
