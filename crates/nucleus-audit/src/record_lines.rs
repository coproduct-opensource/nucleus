//! Reading a line-oriented record log, with a tear classified rather than just
//! failed on.
//!
//! Every record-log writer in the workspace appends a record as ONE `O_APPEND` write
//! of `record\n` (`nucleus_jsonl`, #2935). That fixes what a tear can mean:
//!
//! - **A torn tail** — a final segment with no newline — is a write cut off part way:
//!   a crash mid-append. The records before it are whole and are verified; the torn
//!   one is absent, and the verifier says so ([`crate::AuditError::TornTail`]). Still
//!   a failure (ADR 0007 A-1: an absent record is not a verified one), but a named,
//!   expected one, not a parse error.
//! - **A whole line that is not a record** — newline-terminated, but not parseable —
//!   is something no current writer produces. It was altered, or written before
//!   appends were atomic ([`crate::AuditError::NotARecord`]).
//!
//! Before this, both were the same "failed to parse entry at line N", and a crash
//! looked exactly like tampering.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::AuditError;

/// Whole lines of a record log, in order, skipping blank ones.
pub(crate) struct RecordLines<R> {
    reader: R,
    line_no: usize,
    torn_tail: Option<usize>,
}

pub(crate) fn open(path: &Path) -> Result<RecordLines<BufReader<File>>, AuditError> {
    Ok(RecordLines::new(BufReader::new(File::open(path)?)))
}

impl<R: BufRead> RecordLines<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            line_no: 0,
            torn_tail: None,
        }
    }

    /// After iterating: `Err(TornTail)` if the log ended in a torn record, naming
    /// how many records before it were verified.
    pub(crate) fn finish(self, verified: usize) -> Result<(), AuditError> {
        match self.torn_tail {
            Some(line) => Err(AuditError::TornTail { line, verified }),
            None => Ok(()),
        }
    }
}

impl<R: BufRead> Iterator for RecordLines<R> {
    /// `(line number, the line)` for each whole, non-blank line.
    type Item = Result<(usize, String), AuditError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut buf = Vec::new();
            match self.reader.read_until(b'\n', &mut buf) {
                Ok(0) => return None,
                Ok(_) => {}
                Err(e) => return Some(Err(e.into())),
            }
            self.line_no = self.line_no.saturating_add(1);
            let whole = buf.last() == Some(&b'\n');
            let text = String::from_utf8_lossy(&buf);
            if text.trim().is_empty() {
                continue;
            }
            if !whole {
                // The last segment, and no newline: a write cut off part way.
                self.torn_tail = Some(self.line_no);
                return None;
            }
            return Some(Ok((self.line_no, text.trim().to_owned())));
        }
    }
}

/// Parse one whole line as a record, or say it is not one.
pub(crate) fn parse<T: serde::de::DeserializeOwned>(
    line: usize,
    text: &str,
) -> Result<T, AuditError> {
    serde_json::from_str(text).map_err(|source| AuditError::NotARecord { line, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(bytes: &[u8]) -> (Vec<(usize, String)>, Result<(), AuditError>) {
        let mut lines = RecordLines::new(bytes);
        let got: Vec<_> = (&mut lines).map(Result::unwrap).collect();
        let n = got.len();
        (got, lines.finish(n))
    }

    #[test]
    fn a_complete_log_reads_every_record_and_finishes_clean() {
        let (got, end) = read(b"{\"a\":1}\n\n{\"a\":2}\n");
        assert_eq!(got, vec![(1, "{\"a\":1}".into()), (3, "{\"a\":2}".into())]);
        assert!(end.is_ok());
    }

    #[test]
    fn a_final_segment_without_a_newline_is_a_torn_tail_after_the_whole_records() {
        let (got, end) = read(b"{\"a\":1}\n{\"a\":2}\n{\"a\":");
        assert_eq!(
            got.len(),
            2,
            "the whole records before the tear are still read"
        );
        assert!(
            matches!(
                end,
                Err(AuditError::TornTail {
                    line: 3,
                    verified: 2
                })
            ),
            "{end:?}"
        );
    }

    #[test]
    fn a_whole_line_that_is_not_a_record_is_named_as_such() {
        let err = parse::<serde_json::Value>(7, "{\"a\":").unwrap_err();
        assert!(
            matches!(err, AuditError::NotARecord { line: 7, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn trailing_whitespace_without_a_newline_is_not_a_tear() {
        let (got, end) = read(b"{\"a\":1}\n  ");
        assert_eq!(got.len(), 1);
        assert!(end.is_ok());
    }
}
