//! Import limits: the bound on what an untrusted image may make this process do.

use std::io::{self, Read};

/// Bounds on one import. Every one is enforced while reading, not after, so a
/// decompression bomb is refused at the limit rather than after inflating.
///
/// There is deliberately no `Default` (ADR 0007 B-1): [`ImportLimits::standard`]
/// is a named choice, and a caller who wants other bounds says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImportLimits {
    /// Decompressed layer bytes, summed over every layer (overwritten content counts).
    pub max_uncompressed_bytes: u64,
    /// Tar entries, summed over every layer (whiteouts count).
    pub max_entries: u64,
    /// Length in bytes of one entry path or link target, before normalization.
    pub max_path_bytes: u64,
    /// Size of one JSON document: `index.json`, a manifest, an index, a config.
    pub max_metadata_bytes: u64,
}

impl ImportLimits {
    /// 2 GiB of content, 500 000 entries, 4 KiB paths, 4 MiB of JSON per document.
    ///
    /// The flattened tree is held in memory until emission, so the content bound
    /// is also this process's memory bound for an import.
    pub const fn standard() -> Self {
        Self {
            max_uncompressed_bytes: 2_147_483_648,
            max_entries: 500_000,
            max_path_bytes: 4096,
            max_metadata_bytes: 4_194_304,
        }
    }
}

/// A reader that refuses to yield more than a byte budget, and remembers that it did.
///
/// The flag is what lets the caller name the refusal: the tar parser sees only an
/// I/O error, and "the budget ran out" must not be reported as "the tar is corrupt".
pub(crate) struct Bounded<R> {
    inner: R,
    remaining: u64,
    exhausted: bool,
}

impl<R: Read> Bounded<R> {
    pub(crate) fn new(inner: R, remaining: u64) -> Self {
        Self {
            inner,
            remaining,
            exhausted: false,
        }
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.exhausted
    }

    pub(crate) fn remaining(&self) -> u64 {
        self.remaining
    }

    pub(crate) fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for Bounded<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.exhausted {
            return Err(io::Error::other("import byte budget exhausted"));
        }
        let n = self.inner.read(buf)?;
        let n64 = u64::try_from(n).unwrap_or(u64::MAX);
        match self.remaining.checked_sub(n64) {
            Some(left) => {
                self.remaining = left;
                Ok(n)
            }
            None => {
                self.exhausted = true;
                Err(io::Error::other("import byte budget exhausted"))
            }
        }
    }
}
