//! sha256 digests, the pinned image reference, and the hashing adapters every
//! byte of an image passes through.

use std::io::{self, Read, Write};

use sha2::{Digest as _, Sha256};

use crate::error::ImportError;

/// A sha256 content digest, written `sha256:<64 lowercase hex>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Parse `sha256:<64 lowercase hex>`. Any other algorithm is refused by name.
    pub fn parse(s: &str) -> Result<Self, ImportError> {
        let Some((algorithm, encoded)) = s.split_once(':') else {
            return Err(ImportError::MalformedDigest {
                digest: s.to_owned(),
            });
        };
        if algorithm != "sha256" {
            return Err(ImportError::UnsupportedDigestAlgorithm {
                digest: s.to_owned(),
            });
        }
        let lower_hex = encoded
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if encoded.len() != 64 || !lower_hex {
            return Err(ImportError::MalformedDigest {
                digest: s.to_owned(),
            });
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(encoded, &mut out).map_err(|_| ImportError::MalformedDigest {
            digest: s.to_owned(),
        })?;
        Ok(Self(out))
    }

    /// The digest of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// The 64 lowercase hex digits, without the algorithm prefix.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.hex())
    }
}

impl std::fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl serde::Serialize for Sha256Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Sha256Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// An image reference that is pinned by digest.
///
/// The only constructor is [`PinnedReference::parse`], which refuses a
/// tag-only reference: a tag can move between the decision to import and the
/// import, and a digest cannot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedReference {
    digest: Sha256Digest,
}

impl PinnedReference {
    /// Parse `name@sha256:…` or a bare `sha256:…`. `name:tag` is refused.
    pub fn parse(reference: &str) -> Result<Self, ImportError> {
        if let Some((_, digest)) = reference.rsplit_once('@') {
            return Sha256Digest::parse(digest).map(|digest| Self { digest });
        }
        match reference.split_once(':') {
            Some(("sha256" | "sha384" | "sha512", _)) => {
                Sha256Digest::parse(reference).map(|digest| Self { digest })
            }
            Some(_) | None => Err(ImportError::TagOnlyReference {
                reference: reference.to_owned(),
            }),
        }
    }

    /// The pinned digest: a manifest, or an index that the platform selects within.
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// A reader that hashes and counts everything read through it.
pub(crate) struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    count: u64,
}

impl<R: Read> HashingReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            count: 0,
        }
    }

    /// The inner reader, the digest of what was read, and how many bytes.
    pub(crate) fn finish(self) -> (R, Sha256Digest, u64) {
        (
            self.inner,
            Sha256Digest(self.hasher.finalize().into()),
            self.count,
        )
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        let read = buf
            .get(..n)
            .ok_or_else(|| io::Error::other("reader reported more bytes than the buffer holds"))?;
        self.hasher.update(read);
        self.count = self
            .count
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        Ok(n)
    }
}

/// A writer that hashes and counts everything written through it.
pub(crate) struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
    count: u64,
}

impl<W: Write> HashingWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            count: 0,
        }
    }

    pub(crate) fn finish(self) -> (W, Sha256Digest, u64) {
        (
            self.inner,
            Sha256Digest(self.hasher.finalize().into()),
            self.count,
        )
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        let written = buf
            .get(..n)
            .ok_or_else(|| io::Error::other("writer reported more bytes than the buffer holds"))?;
        self.hasher.update(written);
        self.count = self
            .count
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn digest_round_trips_and_matches_sha256_of_empty() {
        let d = Sha256Digest::parse(&format!("sha256:{HEX}")).unwrap();
        assert_eq!(d, Sha256Digest::of(b""));
        assert_eq!(d.to_string(), format!("sha256:{HEX}"));
    }

    #[test]
    fn digest_refuses_uppercase_short_and_other_algorithms() {
        assert!(matches!(
            Sha256Digest::parse(&format!("sha256:{}", HEX.to_uppercase())),
            Err(ImportError::MalformedDigest { .. })
        ));
        assert!(matches!(
            Sha256Digest::parse("sha256:abcd"),
            Err(ImportError::MalformedDigest { .. })
        ));
        assert!(matches!(
            Sha256Digest::parse(&format!("sha512:{HEX}")),
            Err(ImportError::UnsupportedDigestAlgorithm { .. })
        ));
    }

    #[test]
    fn reference_requires_a_digest() {
        assert!(matches!(
            PinnedReference::parse("docker.io/library/busybox:1.36"),
            Err(ImportError::TagOnlyReference { .. })
        ));
        assert!(matches!(
            PinnedReference::parse("busybox"),
            Err(ImportError::TagOnlyReference { .. })
        ));
        let pinned =
            PinnedReference::parse(&format!("registry:5000/busybox:1.36@sha256:{HEX}")).unwrap();
        assert_eq!(pinned.digest(), Sha256Digest::of(b""));
        assert_eq!(
            PinnedReference::parse(&format!("sha256:{HEX}"))
                .unwrap()
                .digest(),
            Sha256Digest::of(b"")
        );
    }
}
