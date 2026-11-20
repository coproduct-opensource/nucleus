//! Applying a program: one streaming pass, the same bytes out on every
//! platform.
//!
//! # The arithmetic
//!
//! `add_scalar` is defined for two element types, on bit patterns:
//!
//! - **Single precision.** Each element becomes `element + value`, the IEEE
//!   754 single-precision sum, rounded to nearest with ties to even.
//! - **The 16-bit truncation of single precision.** Each element is widened to
//!   single precision exactly (its 16 bits become the high 16, the low 16 are
//!   zero), `value` is added as above, and the sum is rounded back to 16 bits,
//!   to nearest with ties to even.
//!
//! No other element type is patched, and no library's cast is consulted: the
//! rounding is written out below. An element that is infinite or not a number
//! before the operation, or would be after it, refuses the whole patch — a
//! patch never manufactures or launders a non-finite weight.
//!
//! # What comes back
//!
//! [`Applied`] holds the digest of every tensor before and after, computed
//! from the bytes that were read and the bytes that were written in the same
//! pass. It has no public constructor. The write set a release decision rests
//! on is derived from it ([`Applied::diff`]), never from the program.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};

use crate::container::{Dtype, Header, HeaderError};
use crate::digest::{CheckpointIndex, TensorHasher};
use crate::program::{Op, PatchProgram, Scalar};
use crate::writes::{Diff, DiffError, diff};

/// Bytes moved per step. A multiple of every element size.
const CHUNK: usize = 64 * 1024;

/// Why a patch was not applied.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// A file's header was refused.
    #[error(transparent)]
    Header(#[from] HeaderError),
    /// Tensor bytes could not be read or written.
    #[error("moving tensor bytes: {0}")]
    Io(#[from] io::Error),
    /// A file holds bytes after its last tensor.
    #[error("the file holds bytes after its last tensor")]
    TrailingBytes,
    /// A tensor appears in more than one file.
    #[error("tensor {tensor:?} appears in more than one file")]
    DuplicateTensor {
        /// The tensor.
        tensor: String,
    },
    /// The program names tensors the checkpoint does not have.
    #[error("the program names tensors the checkpoint does not have: {tensors:?}")]
    UnknownTensors {
        /// Every such tensor.
        tensors: BTreeSet<String>,
    },
    /// The operation is not defined for the tensor's element type.
    #[error("tensor {tensor:?} has element type {dtype}; the operation is not defined for it")]
    UnsupportedDtype {
        /// The tensor.
        tensor: String,
        /// Its element type.
        dtype: Dtype,
    },
    /// An element is, or would become, infinite or not a number.
    #[error("tensor {tensor:?} has an element that is not finite before or after the operation")]
    NonFinite {
        /// The tensor.
        tensor: String,
    },
}

/// The outcome of applying a program: every tensor's digest before and after.
///
/// Minted only by [`Applier::finish`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    base: CheckpointIndex,
    output: CheckpointIndex,
}

impl Applied {
    /// The checkpoint that was read.
    #[must_use]
    pub const fn base(&self) -> &CheckpointIndex {
        &self.base
    }

    /// The checkpoint that was written.
    #[must_use]
    pub const fn output(&self) -> &CheckpointIndex {
        &self.output
    }

    /// The tensors whose bytes changed.
    ///
    /// # Errors
    ///
    /// [`DiffError`] if the two checkpoints do not hold the same tensor names.
    /// A program cannot cause that; the check is here so the claim does not
    /// rest on that argument.
    pub fn diff(&self) -> Result<Diff, DiffError> {
        diff(&self.base, &self.output)
    }
}

/// Applies one program across the files of one checkpoint.
///
/// Feed every file through [`Applier::file`], then call [`Applier::finish`].
/// Both take the applier by value: an error consumes it, so a half-applied
/// checkpoint cannot be finished.
#[derive(Debug)]
pub struct Applier<'p> {
    ops: BTreeMap<&'p str, Scalar>,
    applied: BTreeSet<&'p str>,
    base: CheckpointIndex,
    output: CheckpointIndex,
}

impl<'p> Applier<'p> {
    /// An applier for `program`.
    #[must_use]
    pub fn new(program: &'p PatchProgram) -> Self {
        let ops = program
            .ops()
            .iter()
            .map(|op| match op {
                Op::AddScalar { tensor, value } => (tensor.as_str(), *value),
            })
            .collect();
        Self {
            ops,
            applied: BTreeSet::new(),
            base: CheckpointIndex::empty(),
            output: CheckpointIndex::empty(),
        }
    }

    /// Reads one checkpoint file from `reader` and writes it, patched, to
    /// `writer`. The header is carried over byte for byte.
    ///
    /// # Errors
    ///
    /// Any [`ApplyError`]. What `writer` received before the error is not a
    /// checkpoint and must be discarded.
    pub fn file<R: Read, W: Write>(
        mut self,
        mut reader: R,
        mut writer: W,
    ) -> Result<Self, ApplyError> {
        let header = Header::read(&mut reader)?;
        writer.write_all(header.raw())?;

        let mut buf = vec![0u8; CHUNK];
        for (name, info) in header.tensors() {
            let op: Option<(&'p str, Scalar)> = self.ops.get_key_value(name).map(|(k, v)| (*k, *v));
            if op.is_some() {
                match info.dtype() {
                    Dtype::F32 | Dtype::Bf16 => {}
                    dtype @ (Dtype::Bool
                    | Dtype::U8
                    | Dtype::I8
                    | Dtype::I16
                    | Dtype::U16
                    | Dtype::F16
                    | Dtype::I32
                    | Dtype::U32
                    | Dtype::F64
                    | Dtype::I64
                    | Dtype::U64) => {
                        return Err(ApplyError::UnsupportedDtype {
                            tensor: name.to_owned(),
                            dtype,
                        });
                    }
                }
            }

            let hasher = || TensorHasher::new(name, info.dtype(), info.shape(), info.byte_len());
            let mut before = hasher();
            let mut after = op.map(|_| hasher());

            let mut remaining = info.byte_len();
            while remaining > 0 {
                let step = usize::try_from(remaining).map_or(CHUNK, |r| r.min(CHUNK));
                let chunk = prefix_mut(&mut buf, step);
                reader.read_exact(chunk)?;
                before.update(chunk);
                if let (Some((_, value)), Some(after)) = (op, after.as_mut()) {
                    let finite = match info.dtype() {
                        Dtype::F32 => add_f32(chunk, value.to_f32()),
                        Dtype::Bf16 => add_bf16(chunk, value.to_f32()),
                        // Refused above, before any byte moved.
                        Dtype::Bool
                        | Dtype::U8
                        | Dtype::I8
                        | Dtype::I16
                        | Dtype::U16
                        | Dtype::F16
                        | Dtype::I32
                        | Dtype::U32
                        | Dtype::F64
                        | Dtype::I64
                        | Dtype::U64 => false,
                    };
                    if !finite {
                        return Err(ApplyError::NonFinite {
                            tensor: name.to_owned(),
                        });
                    }
                    after.update(chunk);
                }
                writer.write_all(chunk)?;
                let moved = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                remaining = remaining.saturating_sub(moved);
            }

            let before = before.finish();
            let after = after.map_or(before, TensorHasher::finish);
            let duplicate = |tensor| ApplyError::DuplicateTensor { tensor };
            self.base
                .insert(name.to_owned(), before)
                .map_err(duplicate)?;
            self.output
                .insert(name.to_owned(), after)
                .map_err(duplicate)?;
            if let Some((target, _)) = op {
                self.applied.insert(target);
            }
        }

        let mut probe = [0u8; 1];
        match reader.read_exact(&mut probe) {
            Ok(()) => return Err(ApplyError::TrailingBytes),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(e) => return Err(ApplyError::Io(e)),
        }
        writer.flush()?;
        Ok(self)
    }

    /// Closes the checkpoint.
    ///
    /// # Errors
    ///
    /// [`ApplyError::UnknownTensors`] if any operation's tensor was in none of
    /// the files. An operation that did not run is not a smaller patch; it is
    /// a different one from the program the proposal bound.
    pub fn finish(self) -> Result<Applied, ApplyError> {
        let Self {
            ops,
            applied,
            base,
            output,
        } = self;
        let missing: BTreeSet<String> = ops
            .keys()
            .filter(|target| !applied.contains(*target))
            .map(|target| (*target).to_owned())
            .collect();
        if !missing.is_empty() {
            return Err(ApplyError::UnknownTensors { tensors: missing });
        }
        Ok(Applied { base, output })
    }
}

/// Reads the files of one checkpoint and returns its index, changing nothing.
///
/// This is how a party that did not apply a patch measures a checkpoint it was
/// handed: an evaluator before it scores a candidate, a server before it
/// serves one.
#[derive(Debug)]
pub struct Indexer(Applier<'static>);

impl Indexer {
    /// An indexer with no files read.
    #[must_use]
    pub const fn start() -> Self {
        Self(Applier {
            ops: BTreeMap::new(),
            applied: BTreeSet::new(),
            base: CheckpointIndex::empty(),
            output: CheckpointIndex::empty(),
        })
    }

    /// Reads one checkpoint file.
    ///
    /// # Errors
    ///
    /// Any [`ApplyError`] a read can produce: a refused header, a short or
    /// over-long file, a tensor already seen in an earlier file.
    pub fn file<R: Read>(self, reader: R) -> Result<Self, ApplyError> {
        self.0.file(reader, io::sink()).map(Self)
    }

    /// The index of everything read.
    #[must_use]
    pub fn finish(self) -> CheckpointIndex {
        let Self(Applier {
            ops: _,
            applied: _,
            base,
            output: _,
        }) = self;
        base
    }
}

/// The first `n` bytes of `buf`, or all of it if it is shorter.
fn prefix_mut(buf: &mut [u8], n: usize) -> &mut [u8] {
    let n = n.min(buf.len());
    buf.split_at_mut(n).0
}

/// Adds `value` to each little-endian single-precision element. Returns
/// whether every element was finite before and after, and the bytes were a
/// whole number of elements.
fn add_f32(chunk: &mut [u8], value: f32) -> bool {
    let (elements, rest) = chunk.as_chunks_mut::<4>();
    for element in elements {
        let before = f32::from_le_bytes(*element);
        let after = before + value;
        if !(before.is_finite() && after.is_finite()) {
            return false;
        }
        *element = after.to_le_bytes();
    }
    rest.is_empty()
}

/// As [`add_f32`], for the 16-bit truncation of single precision.
fn add_bf16(chunk: &mut [u8], value: f32) -> bool {
    let (elements, rest) = chunk.as_chunks_mut::<2>();
    for element in elements {
        let [lo, hi] = *element;
        let before = f32::from_bits(u32::from_be_bytes([hi, lo, 0, 0]));
        let sum = before + value;
        if !(before.is_finite() && sum.is_finite()) {
            return false;
        }
        let [hi, lo] = round_to_bf16(sum);
        // Rounding up from the largest finite value lands on infinity.
        if !f32::from_bits(u32::from_be_bytes([hi, lo, 0, 0])).is_finite() {
            return false;
        }
        *element = [lo, hi];
    }
    rest.is_empty()
}

/// Rounds a finite single-precision value to its high 16 bits, to nearest
/// with ties to even, returned big-endian.
///
/// Adding `0x7fff` plus the lowest kept bit carries into the kept half exactly
/// when the discarded half is above one half, or is one half and the kept half
/// is odd. For a finite input the sum cannot wrap: the largest magnitude is
/// `0x7f7f_ffff`.
fn round_to_bf16(value: f32) -> [u8; 2] {
    let bits = value.to_bits();
    let [_, kept_low, _, _] = bits.to_be_bytes();
    let tie_to_even = u32::from(kept_low & 1);
    let rounded = bits.wrapping_add(0x7fff).wrapping_add(tie_to_even);
    let [hi, lo, _, _] = rounded.to_be_bytes();
    [hi, lo]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::write_checkpoint;

    fn add(tensor: &str, value: f32) -> Op {
        Op::AddScalar {
            tensor: tensor.to_owned(),
            value: Scalar::from_f32(value).unwrap(),
        }
    }

    fn program(ops: Vec<Op>) -> PatchProgram {
        PatchProgram::new(ops).unwrap()
    }

    fn checkpoint(tensors: &[(&str, Dtype, &[u64], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        write_checkpoint(tensors, &mut out).unwrap();
        out
    }

    fn apply(file: &[u8], program: &PatchProgram) -> Result<(Applied, Vec<u8>), ApplyError> {
        let mut out = Vec::new();
        let applied = Applier::new(program).file(file, &mut out)?.finish()?;
        Ok((applied, out))
    }

    fn bf16(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn f32s(values: &[f32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    /// The data bytes of a one-tensor file: everything after the header.
    fn data(file: &[u8]) -> &[u8] {
        let header = Header::read(&mut &*file).unwrap();
        &file[header.raw().len()..]
    }

    #[test]
    fn bf16_golden_vectors() {
        // (before, value, after), each a 16-bit pattern.
        let cases: &[(u16, f32, u16)] = &[
            (0x0000, 0.5, 0x3f00), // 0 + 0.5 = 0.5
            (0x3f80, 0.5, 0x3fc0), // 1 + 0.5 = 1.5
            (0xbf00, 0.5, 0x0000), // -0.5 + 0.5 = +0
            (0xbf80, 0.5, 0xbf00), // -1 + 0.5 = -0.5
            (0x4380, 0.5, 0x4380), // 256 + 0.5: below half a step of 2, unchanged
            (0x4380, 1.0, 0x4380), // 257 is a tie between 256 and 258: even is 256
            (0x4381, 1.0, 0x4382), // 259 is a tie between 258 and 260: even is 260
            (0x4380, 1.5, 0x4381), // 257.5 is above the tie: 258
            (0xc381, 1.0, 0xc380), // -258 + 1 = -257, a tie: even is -256
        ];
        for &(before, value, after) in cases {
            let file = checkpoint(&[("t", Dtype::Bf16, &[1], &bf16(&[before]))]);
            let (_, out) = apply(&file, &program(vec![add("t", value)])).unwrap();
            assert_eq!(
                data(&out),
                bf16(&[after]),
                "{before:#06x} + {value} should be {after:#06x}"
            );
        }
    }

    #[test]
    fn f32_golden_vectors() {
        let file = checkpoint(&[("t", Dtype::F32, &[3], &f32s(&[0.0, 1.0, -0.5]))]);
        let (_, out) = apply(&file, &program(vec![add("t", 0.5)])).unwrap();
        assert_eq!(data(&out), f32s(&[0.5, 1.5, 0.0]));
    }

    #[test]
    fn only_the_named_tensor_changes_and_the_header_is_carried_over() {
        let file = checkpoint(&[
            ("embed", Dtype::F32, &[2], &f32s(&[1.0, 2.0])),
            ("bias", Dtype::Bf16, &[2], &bf16(&[0x3f80, 0x0000])),
            ("ids", Dtype::I64, &[1], &[9; 8]),
        ]);
        let (applied, out) = apply(&file, &program(vec![add("bias", 0.5)])).unwrap();

        let header_len = Header::read(&mut &*file).unwrap().raw().len();
        assert_eq!(&out[..header_len], &file[..header_len]);
        assert_eq!(out.len(), file.len());

        let changed: Vec<_> = applied
            .base()
            .iter()
            .filter(|(name, d)| applied.output().get(name) != Some(*d))
            .map(|(name, _)| name)
            .collect();
        assert_eq!(changed, ["bias"]);
        assert_ne!(applied.base().digest(), applied.output().digest());
    }

    #[test]
    fn applying_twice_gives_the_same_bytes() {
        let file = checkpoint(&[("bias", Dtype::Bf16, &[3], &bf16(&[0x3f80, 0x4380, 0xbf00]))]);
        let p = program(vec![add("bias", 0.5)]);
        let (one, out_one) = apply(&file, &p).unwrap();
        let (two, out_two) = apply(&file, &p).unwrap();
        assert_eq!(out_one, out_two);
        assert_eq!(one, two);
    }

    #[test]
    fn the_output_digest_is_the_digest_of_the_output_file() {
        let file = checkpoint(&[
            ("a", Dtype::F32, &[1], &f32s(&[1.0])),
            ("b", Dtype::F32, &[1], &f32s(&[2.0])),
        ]);
        let (applied, out) = apply(&file, &program(vec![add("a", 0.5)])).unwrap();
        let reread = Indexer::start().file(&*out).unwrap().finish();
        assert_eq!(reread.digest(), applied.output().digest());
        assert_eq!(&reread, applied.output());
    }

    #[test]
    fn the_digest_does_not_depend_on_how_tensors_are_split_across_files() {
        let (a_bytes, b_bytes) = (f32s(&[1.0]), bf16(&[0x3f80]));
        let shape: &[u64] = &[1];
        let a = ("a", Dtype::F32, shape, a_bytes.as_slice());
        let b = ("b", Dtype::Bf16, shape, b_bytes.as_slice());
        let p = program(vec![add("b", 0.5)]);

        let (whole, _) = apply(&checkpoint(&[a, b]), &p).unwrap();
        let split = Applier::new(&p)
            .file(&*checkpoint(&[b]), io::sink())
            .unwrap()
            .file(&*checkpoint(&[a]), io::sink())
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(split, whole);
    }

    #[test]
    fn a_tensor_in_two_files_is_refused() {
        let file = checkpoint(&[("a", Dtype::F32, &[1], &f32s(&[1.0]))]);
        let p = program(vec![add("a", 0.5)]);
        let result = Applier::new(&p)
            .file(&*file, io::sink())
            .unwrap()
            .file(&*file, io::sink());
        assert!(matches!(result, Err(ApplyError::DuplicateTensor { .. })));
    }

    #[test]
    fn an_operation_that_did_not_run_refuses_the_patch() {
        let file = checkpoint(&[("a", Dtype::F32, &[1], &f32s(&[1.0]))]);
        let p = program(vec![add("a", 0.5), add("missing", 0.5)]);
        match apply(&file, &p) {
            Err(ApplyError::UnknownTensors { tensors }) => {
                assert_eq!(tensors.into_iter().collect::<Vec<_>>(), ["missing"]);
            }
            other => panic!("expected UnknownTensors, got {other:?}"),
        }
    }

    #[test]
    fn an_integer_tensor_is_refused() {
        let file = checkpoint(&[("ids", Dtype::I32, &[1], &[0; 4])]);
        assert!(matches!(
            apply(&file, &program(vec![add("ids", 0.5)])),
            Err(ApplyError::UnsupportedDtype {
                dtype: Dtype::I32,
                ..
            })
        ));
    }

    #[test]
    fn a_non_finite_element_is_refused_before_and_after() {
        let nan = checkpoint(&[("t", Dtype::F32, &[1], &f32s(&[f32::NAN]))]);
        let inf = checkpoint(&[("t", Dtype::Bf16, &[1], &bf16(&[0x7f80]))]);
        let max = checkpoint(&[("t", Dtype::F32, &[1], &f32s(&[f32::MAX]))]);
        let max16 = checkpoint(&[("t", Dtype::Bf16, &[1], &bf16(&[0x7f7f]))]);
        let half = program(vec![add("t", 0.5)]);
        let huge = program(vec![add("t", f32::MAX)]);
        for (file, p) in [(&nan, &half), (&inf, &half), (&max, &huge), (&max16, &huge)] {
            assert!(matches!(apply(file, p), Err(ApplyError::NonFinite { .. })));
        }
    }

    #[test]
    fn bytes_after_the_last_tensor_are_refused() {
        let mut file = checkpoint(&[("a", Dtype::F32, &[1], &f32s(&[1.0]))]);
        file.push(0);
        assert!(matches!(
            apply(&file, &program(vec![add("a", 0.5)])),
            Err(ApplyError::TrailingBytes)
        ));
    }

    #[test]
    fn a_truncated_tensor_is_refused() {
        let mut file = checkpoint(&[("a", Dtype::F32, &[2], &f32s(&[1.0, 2.0]))]);
        file.pop();
        assert!(matches!(
            apply(&file, &program(vec![add("a", 0.5)])),
            Err(ApplyError::Io(_))
        ));
    }

    #[test]
    fn a_tensor_longer_than_one_chunk_is_patched_whole() {
        let count = CHUNK + 3;
        let values = vec![1.0f32; count];
        let file = checkpoint(&[(
            "big",
            Dtype::F32,
            &[u64::try_from(count).unwrap()],
            &f32s(&values),
        )]);
        let (_, out) = apply(&file, &program(vec![add("big", 0.5)])).unwrap();
        assert_eq!(data(&out), f32s(&vec![1.5f32; count]));
    }
}
