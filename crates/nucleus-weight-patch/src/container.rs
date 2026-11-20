//! The tensor-file layout: an 8-byte little-endian header length, a JSON
//! header, then the tensor bytes.
//!
//! The header maps each tensor name to its element type, shape and byte range.
//! This reader is stricter than the layout strictly requires, on purpose:
//! every header it accepts has exactly one interpretation. A name given twice,
//! a byte range that overlaps another, a gap that no tensor owns, a shape
//! whose size disagrees with its range — each is a place where two readers
//! could load different weights from one file, so each is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read, Write};

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

/// The largest header this reader will allocate for.
pub const MAX_HEADER_BYTES: u64 = 100 * 1024 * 1024;

/// The key under which a file carries free-form string metadata. It is not a
/// tensor and is not part of any digest.
const METADATA_KEY: &str = "__metadata__";

/// A tensor's element type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Dtype {
    /// One byte per element, zero or one.
    #[serde(rename = "BOOL")]
    Bool,
    /// Unsigned 8-bit integer.
    #[serde(rename = "U8")]
    U8,
    /// Signed 8-bit integer.
    #[serde(rename = "I8")]
    I8,
    /// Signed 16-bit integer.
    #[serde(rename = "I16")]
    I16,
    /// Unsigned 16-bit integer.
    #[serde(rename = "U16")]
    U16,
    /// IEEE 754 half precision.
    #[serde(rename = "F16")]
    F16,
    /// The 16-bit truncation of IEEE 754 single precision.
    #[serde(rename = "BF16")]
    Bf16,
    /// Signed 32-bit integer.
    #[serde(rename = "I32")]
    I32,
    /// Unsigned 32-bit integer.
    #[serde(rename = "U32")]
    U32,
    /// IEEE 754 single precision.
    #[serde(rename = "F32")]
    F32,
    /// IEEE 754 double precision.
    #[serde(rename = "F64")]
    F64,
    /// Signed 64-bit integer.
    #[serde(rename = "I64")]
    I64,
    /// Unsigned 64-bit integer.
    #[serde(rename = "U64")]
    U64,
}

impl Dtype {
    /// Bytes per element.
    #[must_use]
    pub const fn size(self) -> u64 {
        match self {
            Self::Bool | Self::U8 | Self::I8 => 1,
            Self::I16 | Self::U16 | Self::F16 | Self::Bf16 => 2,
            Self::I32 | Self::U32 | Self::F32 => 4,
            Self::F64 | Self::I64 | Self::U64 => 8,
        }
    }

    /// The name this type has in a header, which is also what a tensor digest
    /// binds.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Bool => "BOOL",
            Self::U8 => "U8",
            Self::I8 => "I8",
            Self::I16 => "I16",
            Self::U16 => "U16",
            Self::F16 => "F16",
            Self::Bf16 => "BF16",
            Self::I32 => "I32",
            Self::U32 => "U32",
            Self::F32 => "F32",
            Self::F64 => "F64",
            Self::I64 => "I64",
            Self::U64 => "U64",
        }
    }
}

impl fmt::Display for Dtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// Why a header was refused.
#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    /// The bytes could not be read.
    #[error("reading the header: {0}")]
    Io(#[from] io::Error),
    /// The declared header length exceeds [`MAX_HEADER_BYTES`].
    #[error(
        "the header declares {declared} bytes; the limit is {}",
        MAX_HEADER_BYTES
    )]
    TooLarge {
        /// The length the file declares.
        declared: u64,
    },
    /// The header is not the expected JSON, or names a tensor twice.
    #[error("the header is not a valid tensor map: {0}")]
    Json(#[from] serde_json::Error),
    /// A tensor's byte range ends before it begins.
    #[error("tensor {name:?} has a byte range that ends before it begins")]
    ReversedRange {
        /// The tensor.
        name: String,
    },
    /// A tensor's shape does not have a representable size.
    #[error("tensor {name:?} has a shape whose size overflows")]
    ShapeOverflow {
        /// The tensor.
        name: String,
    },
    /// A tensor's shape and element type disagree with its byte range.
    #[error("tensor {name:?} needs {expected} bytes for its shape; its byte range holds {actual}")]
    SizeMismatch {
        /// The tensor.
        name: String,
        /// Bytes the shape and element type require.
        expected: u64,
        /// Bytes the range holds.
        actual: u64,
    },
    /// The byte ranges do not tile the data: a gap no tensor owns, or an
    /// overlap two tensors share.
    #[error("tensor {name:?} begins at byte {begin}; the previous tensor ends at {expected}")]
    NotContiguous {
        /// The tensor whose range starts in the wrong place.
        name: String,
        /// Where it starts.
        begin: u64,
        /// Where it had to start.
        expected: u64,
    },
}

/// One tensor's entry in a header, validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorInfo {
    dtype: Dtype,
    shape: Vec<u64>,
    begin: u64,
    end: u64,
}

impl TensorInfo {
    /// The element type.
    #[must_use]
    pub const fn dtype(&self) -> Dtype {
        self.dtype
    }

    /// The shape; empty for a scalar.
    #[must_use]
    pub fn shape(&self) -> &[u64] {
        &self.shape
    }

    /// How many bytes the tensor occupies.
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        // `end >= begin` is established by `Header::read` before a
        // `TensorInfo` exists.
        self.end.saturating_sub(self.begin)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawInfo {
    dtype: Dtype,
    shape: Vec<u64>,
    data_offsets: (u64, u64),
}

/// The header's entries in file order, with a repeated name refused.
///
/// Deserialization is written by hand for one reason: a derived map takes the
/// last of two entries with the same key and says nothing, and another reader
/// may take the first.
struct RawEntries(Vec<(String, RawInfo)>);

impl<'de> Deserialize<'de> for RawEntries {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EntriesVisitor;

        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = RawEntries;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map from tensor name to its element type, shape and byte range")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut seen = BTreeSet::new();
                let mut entries = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom(format!("the name {key:?} appears twice")));
                    }
                    if key == METADATA_KEY {
                        map.next_value::<BTreeMap<String, String>>()?;
                    } else {
                        entries.push((key, map.next_value::<RawInfo>()?));
                    }
                }
                Ok(RawEntries(entries))
            }
        }

        deserializer.deserialize_map(EntriesVisitor)
    }
}

/// A validated header: every tensor, in the order its bytes appear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The length prefix and header exactly as read, so a patched file can
    /// carry the same header byte for byte.
    raw: Vec<u8>,
    tensors: Vec<(String, TensorInfo)>,
}

impl Header {
    /// Reads and validates a header, leaving `reader` at the first tensor byte.
    ///
    /// # Errors
    ///
    /// Any [`HeaderError`]: the header is unreadable, too large, not the
    /// expected JSON, or admits more than one interpretation.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, HeaderError> {
        let mut prefix = [0u8; 8];
        reader.read_exact(&mut prefix)?;
        let declared = u64::from_le_bytes(prefix);
        if declared > MAX_HEADER_BYTES {
            return Err(HeaderError::TooLarge { declared });
        }
        let mut raw = prefix.to_vec();
        let copied = reader.by_ref().take(declared).read_to_end(&mut raw)?;
        if u64::try_from(copied).ok() != Some(declared) {
            return Err(HeaderError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        let json = raw.get(prefix.len()..).unwrap_or_default();
        let RawEntries(entries) = serde_json::from_slice(json)?;

        let mut tensors = Vec::with_capacity(entries.len());
        for (name, info) in entries {
            let RawInfo {
                dtype,
                shape,
                data_offsets: (begin, end),
            } = info;
            let Some(actual) = end.checked_sub(begin) else {
                return Err(HeaderError::ReversedRange { name });
            };
            let Some(expected) = shape
                .iter()
                .try_fold(dtype.size(), |acc, dim| acc.checked_mul(*dim))
            else {
                return Err(HeaderError::ShapeOverflow { name });
            };
            if expected != actual {
                return Err(HeaderError::SizeMismatch {
                    name,
                    expected,
                    actual,
                });
            }
            tensors.push((
                name,
                TensorInfo {
                    dtype,
                    shape,
                    begin,
                    end,
                },
            ));
        }

        // Byte order, with an empty tensor ahead of the tensor that starts
        // where it sits, and the name as the last key so the order is total.
        tensors.sort_by(|(an, a), (bn, b)| (a.begin, a.end, an).cmp(&(b.begin, b.end, bn)));
        let mut expected = 0u64;
        for (name, info) in &tensors {
            if info.begin != expected {
                return Err(HeaderError::NotContiguous {
                    name: name.clone(),
                    begin: info.begin,
                    expected,
                });
            }
            expected = info.end;
        }

        Ok(Self { raw, tensors })
    }

    /// The length prefix and header bytes exactly as they were read.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Every tensor, in the order its bytes appear after the header.
    pub fn tensors(&self) -> impl Iterator<Item = (&str, &TensorInfo)> {
        self.tensors.iter().map(|(n, i)| (n.as_str(), i))
    }
}

/// Writes a checkpoint file holding `tensors` in the order given.
///
/// This is how tests and small fixtures are made. It writes exactly what
/// [`Header::read`] accepts, and checks its own output against that reader's
/// rules by construction: each range starts where the last one ended.
///
/// # Errors
///
/// [`HeaderError::SizeMismatch`] or [`HeaderError::ShapeOverflow`] if a
/// tensor's bytes do not match its shape and element type; a JSON error if a
/// name is given twice; an I/O error from `writer`.
pub fn write_checkpoint<W: Write>(
    tensors: &[(&str, Dtype, &[u64], &[u8])],
    writer: &mut W,
) -> Result<(), HeaderError> {
    let mut entries = BTreeMap::new();
    let mut offset = 0u64;
    for (name, dtype, shape, bytes) in tensors {
        let name = (*name).to_owned();
        let Some(expected) = shape
            .iter()
            .try_fold(dtype.size(), |acc, dim| acc.checked_mul(*dim))
        else {
            return Err(HeaderError::ShapeOverflow { name });
        };
        let actual = u64::try_from(bytes.len()).ok();
        let end = actual.and_then(|len| offset.checked_add(len));
        let (Some(actual), Some(end)) = (actual, end) else {
            return Err(HeaderError::ShapeOverflow { name });
        };
        if expected != actual {
            return Err(HeaderError::SizeMismatch {
                name,
                expected,
                actual,
            });
        }
        let info = RawInfo {
            dtype: *dtype,
            shape: shape.to_vec(),
            data_offsets: (offset, end),
        };
        if entries.insert(name.clone(), info).is_some() {
            return Err(HeaderError::Json(de::Error::custom(format!(
                "the name {name:?} appears twice"
            ))));
        }
        offset = end;
    }

    let mut json = serde_json::to_vec(&entries)?;
    // Pad to a multiple of eight so the tensor bytes start aligned.
    while !json.len().is_multiple_of(8) {
        json.push(b' ');
    }
    let Ok(len) = u64::try_from(json.len()) else {
        return Err(HeaderError::TooLarge { declared: u64::MAX });
    };
    if len > MAX_HEADER_BYTES {
        return Err(HeaderError::TooLarge { declared: len });
    }
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&json)?;
    for (_, _, _, bytes) in tensors {
        writer.write_all(bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(header: &str, data: &[u8]) -> Vec<u8> {
        let mut out = u64::try_from(header.len()).unwrap().to_le_bytes().to_vec();
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(data);
        out
    }

    fn read(bytes: &[u8]) -> Result<Header, HeaderError> {
        Header::read(&mut &*bytes)
    }

    #[test]
    fn what_the_writer_writes_the_reader_accepts() {
        let mut out = Vec::new();
        write_checkpoint(
            &[
                ("b", Dtype::F32, &[2], &[0; 8]),
                ("a", Dtype::Bf16, &[1, 3], &[0; 6]),
                ("s", Dtype::U8, &[], &[7]),
            ],
            &mut out,
        )
        .unwrap();
        let header = read(&out).unwrap();
        let names: Vec<_> = header.tensors().map(|(n, _)| n).collect();
        assert_eq!(names, ["b", "a", "s"], "byte order, not name order");
        let sizes: Vec<_> = header.tensors().map(|(_, i)| i.byte_len()).collect();
        assert_eq!(sizes, [8, 6, 1]);
        assert!(header.raw().len().is_multiple_of(8));
    }

    #[test]
    fn metadata_is_not_a_tensor() {
        let h = r#"{"__metadata__":{"k":"v"},"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}"#;
        let header = read(&file(h, &[0])).unwrap();
        assert_eq!(header.tensors().count(), 1);
    }

    #[test]
    fn a_name_given_twice_is_refused() {
        let h = r#"{"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"a":{"dtype":"U8","shape":[1],"data_offsets":[1,2]}}"#;
        assert!(matches!(read(&file(h, &[0, 0])), Err(HeaderError::Json(_))));
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let h = r#"{"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1],"x":1}}"#;
        assert!(matches!(read(&file(h, &[0])), Err(HeaderError::Json(_))));
    }

    #[test]
    fn a_shape_that_disagrees_with_its_range_is_refused() {
        let h = r#"{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,4]}}"#;
        assert!(matches!(
            read(&file(h, &[0; 4])),
            Err(HeaderError::SizeMismatch {
                expected: 8,
                actual: 4,
                ..
            })
        ));
    }

    #[test]
    fn a_gap_is_refused() {
        let h = r#"{"a":{"dtype":"U8","shape":[1],"data_offsets":[1,2]}}"#;
        assert!(matches!(
            read(&file(h, &[0, 0])),
            Err(HeaderError::NotContiguous {
                begin: 1,
                expected: 0,
                ..
            })
        ));
    }

    #[test]
    fn an_overlap_is_refused() {
        let h = r#"{"a":{"dtype":"U8","shape":[2],"data_offsets":[0,2]},"b":{"dtype":"U8","shape":[2],"data_offsets":[1,3]}}"#;
        assert!(matches!(
            read(&file(h, &[0; 3])),
            Err(HeaderError::NotContiguous {
                begin: 1,
                expected: 2,
                ..
            })
        ));
    }

    #[test]
    fn a_reversed_range_is_refused() {
        let h = r#"{"a":{"dtype":"U8","shape":[1],"data_offsets":[2,1]}}"#;
        assert!(matches!(
            read(&file(h, &[0; 2])),
            Err(HeaderError::ReversedRange { .. })
        ));
    }

    #[test]
    fn an_overflowing_shape_is_refused() {
        let h = r#"{"a":{"dtype":"F64","shape":[4294967296,4294967296],"data_offsets":[0,8]}}"#;
        assert!(matches!(
            read(&file(h, &[0; 8])),
            Err(HeaderError::ShapeOverflow { .. })
        ));
    }

    #[test]
    fn an_oversized_header_is_refused_before_it_is_allocated() {
        let bytes = u64::MAX.to_le_bytes();
        assert!(matches!(
            read(&bytes),
            Err(HeaderError::TooLarge { declared: u64::MAX })
        ));
    }

    #[test]
    fn a_truncated_header_is_refused() {
        let mut bytes = 100u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        assert!(matches!(read(&bytes), Err(HeaderError::Io(_))));
    }

    #[test]
    fn an_empty_tensor_shares_an_offset() {
        let h = r#"{"z":{"dtype":"F32","shape":[0],"data_offsets":[0,0]},"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}"#;
        let header = read(&file(h, &[9])).unwrap();
        let names: Vec<_> = header.tensors().map(|(n, _)| n).collect();
        assert_eq!(names, ["z", "a"]);
    }
}
