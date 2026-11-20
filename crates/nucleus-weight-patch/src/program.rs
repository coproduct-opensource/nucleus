//! The patch program: what a proposal says it will do to a checkpoint.
//!
//! A program is data. It names each tensor it changes, one operation per
//! tensor, and carries no code and no patterns: the set of tensors a program
//! can write is readable from the program without running it. Its digest is
//! what a proposal binds, and anyone holding the base checkpoint and the
//! program can recover the candidate.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use crate::digest::ProgramDigest;

/// The one schema this crate reads and writes.
pub const PROGRAM_SCHEMA: &str = "nucleus.weight_patch.program.v1";

const PROGRAM_DOMAIN: &[u8] = b"nucleus/weight-patch/program/v1\0";

/// Why a program was refused.
#[derive(Debug, thiserror::Error)]
pub enum ProgramError {
    /// The schema is not [`PROGRAM_SCHEMA`].
    #[error(
        "unknown program schema {got:?}; this reader knows {:?}",
        PROGRAM_SCHEMA
    )]
    UnknownSchema {
        /// The schema the program declares.
        got: String,
    },
    /// The program has no operations. A proposal that changes nothing is not a
    /// proposal, and an empty write set must never be mistaken for a wildcard.
    #[error("a program has at least one operation")]
    Empty,
    /// Two operations name the same tensor.
    #[error("tensor {tensor:?} is the target of more than one operation")]
    DuplicateTarget {
        /// The tensor named twice.
        tensor: String,
    },
    /// A scalar is not written as `0x` and eight lowercase hexadecimal digits.
    #[error("a scalar is `0x` and eight lowercase hexadecimal digits; got {got:?}")]
    ScalarSpelling {
        /// The text that was given.
        got: String,
    },
    /// A scalar is infinite or not a number.
    #[error("a scalar is finite")]
    ScalarNotFinite,
    /// The program could not be put in canonical form.
    #[error("canonical form: {0}")]
    Canonical(#[from] serde_json::Error),
}

/// A finite single-precision value, carried as its bit pattern.
///
/// It is written `0x3f000000`, not `0.5`: a decimal has to be parsed, and two
/// parsers that round differently would apply two different patches under one
/// program digest.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Scalar {
    bits: u32,
}

impl Scalar {
    /// The scalar for a finite `f32`.
    ///
    /// # Errors
    ///
    /// [`ProgramError::ScalarNotFinite`] for an infinity or a NaN.
    pub fn from_f32(value: f32) -> Result<Self, ProgramError> {
        if value.is_finite() {
            Ok(Self {
                bits: value.to_bits(),
            })
        } else {
            Err(ProgramError::ScalarNotFinite)
        }
    }

    /// The value.
    #[must_use]
    pub const fn to_f32(self) -> f32 {
        f32::from_bits(self.bits)
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scalar({:#010x} = {})", self.bits, self.to_f32())
    }
}

impl From<Scalar> for String {
    fn from(s: Scalar) -> Self {
        format!("{:#010x}", s.bits)
    }
}

impl TryFrom<String> for Scalar {
    type Error = ProgramError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let parsed = s
            .strip_prefix("0x")
            .filter(|digits| digits.len() == 8)
            .and_then(|digits| u32::from_str_radix(digits, 16).ok())
            .map(|bits| Self { bits })
            // One value, one spelling: `from_str_radix` takes upper case and a
            // leading `+`.
            .filter(|scalar| String::from(*scalar) == s);
        match parsed {
            Some(scalar) => Self::from_f32(scalar.to_f32()),
            None => Err(ProgramError::ScalarSpelling { got: s }),
        }
    }
}

/// One operation on one named tensor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    /// Add `value` to every element of `tensor`.
    ///
    /// Defined for single precision and for its 16-bit truncation; see
    /// [`crate::apply`] for the exact arithmetic.
    AddScalar {
        /// The tensor to change.
        tensor: String,
        /// The value added to each element.
        value: Scalar,
    },
}

impl Op {
    /// The tensor this operation writes.
    #[must_use]
    pub fn tensor(&self) -> &str {
        match self {
            Self::AddScalar { tensor, value: _ } => tensor,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProgram {
    schema: String,
    ops: Vec<Op>,
}

/// A validated patch program and its digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawProgram", into = "RawProgram")]
pub struct PatchProgram {
    ops: Vec<Op>,
    digest: ProgramDigest,
}

impl PatchProgram {
    /// A program of `ops`, applied as one step.
    ///
    /// # Errors
    ///
    /// [`ProgramError::Empty`] for no operations;
    /// [`ProgramError::DuplicateTarget`] if two name one tensor.
    pub fn new(ops: Vec<Op>) -> Result<Self, ProgramError> {
        if ops.is_empty() {
            return Err(ProgramError::Empty);
        }
        let mut seen = BTreeSet::new();
        for op in &ops {
            if !seen.insert(op.tensor()) {
                return Err(ProgramError::DuplicateTarget {
                    tensor: op.tensor().to_owned(),
                });
            }
        }
        // The struct holds no map, so its JSON has one byte sequence.
        let canonical = serde_json::to_vec(&RawProgram {
            schema: PROGRAM_SCHEMA.to_owned(),
            ops: ops.clone(),
        })?;
        let mut h = Sha256::new();
        h.update(PROGRAM_DOMAIN);
        h.update(&canonical);
        let digest = ProgramDigest::from_bytes(h.finalize().into());
        Ok(Self { ops, digest })
    }

    /// The operations, in program order.
    #[must_use]
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    /// Every tensor the program writes.
    #[must_use]
    pub fn targets(&self) -> BTreeSet<&str> {
        self.ops.iter().map(Op::tensor).collect()
    }

    /// The digest a proposal binds.
    #[must_use]
    pub const fn digest(&self) -> ProgramDigest {
        self.digest
    }
}

impl TryFrom<RawProgram> for PatchProgram {
    type Error = ProgramError;

    fn try_from(raw: RawProgram) -> Result<Self, Self::Error> {
        let RawProgram { schema, ops } = raw;
        if schema != PROGRAM_SCHEMA {
            return Err(ProgramError::UnknownSchema { got: schema });
        }
        Self::new(ops)
    }
}

impl From<PatchProgram> for RawProgram {
    fn from(program: PatchProgram) -> Self {
        let PatchProgram { ops, digest: _ } = program;
        Self {
            schema: PROGRAM_SCHEMA.to_owned(),
            ops,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(tensor: &str, value: f32) -> Op {
        Op::AddScalar {
            tensor: tensor.to_owned(),
            value: Scalar::from_f32(value).unwrap(),
        }
    }

    #[test]
    fn a_scalar_has_one_spelling() {
        let half = Scalar::from_f32(0.5).unwrap();
        assert_eq!(String::from(half), "0x3f000000");
        assert_eq!(Scalar::try_from("0x3f000000".to_owned()).unwrap(), half);
        for bad in ["0x3F000000", "3f000000", "0x3f0000", "0x+f000000", "0.5"] {
            assert!(
                matches!(
                    Scalar::try_from(bad.to_owned()),
                    Err(ProgramError::ScalarSpelling { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_scalar_is_finite() {
        assert!(Scalar::from_f32(f32::INFINITY).is_err());
        assert!(Scalar::from_f32(f32::NAN).is_err());
        assert!(matches!(
            Scalar::try_from("0x7f800000".to_owned()),
            Err(ProgramError::ScalarNotFinite)
        ));
    }

    #[test]
    fn a_program_round_trips_and_keeps_its_digest() {
        let program = PatchProgram::new(vec![add("layer.0.bias", 0.5)]).unwrap();
        let json = serde_json::to_string(&program).unwrap();
        assert_eq!(
            json,
            r#"{"schema":"nucleus.weight_patch.program.v1","ops":[{"op":"add_scalar","tensor":"layer.0.bias","value":"0x3f000000"}]}"#
        );
        let back: PatchProgram = serde_json::from_str(&json).unwrap();
        assert_eq!(back, program);
        assert_eq!(back.digest(), program.digest());
    }

    #[test]
    fn the_digest_binds_tensor_value_and_order() {
        let base = PatchProgram::new(vec![add("a", 0.5), add("b", 0.5)]).unwrap();
        let other_value = PatchProgram::new(vec![add("a", 0.25), add("b", 0.5)]).unwrap();
        let other_tensor = PatchProgram::new(vec![add("a", 0.5), add("c", 0.5)]).unwrap();
        let other_order = PatchProgram::new(vec![add("b", 0.5), add("a", 0.5)]).unwrap();
        assert_ne!(base.digest(), other_value.digest());
        assert_ne!(base.digest(), other_tensor.digest());
        assert_ne!(base.digest(), other_order.digest());
    }

    #[test]
    fn an_empty_program_is_refused() {
        assert!(matches!(
            PatchProgram::new(Vec::new()),
            Err(ProgramError::Empty)
        ));
        let json = r#"{"schema":"nucleus.weight_patch.program.v1","ops":[]}"#;
        assert!(serde_json::from_str::<PatchProgram>(json).is_err());
    }

    #[test]
    fn two_operations_on_one_tensor_are_refused() {
        assert!(matches!(
            PatchProgram::new(vec![add("a", 0.5), add("a", 0.25)]),
            Err(ProgramError::DuplicateTarget { .. })
        ));
    }

    #[test]
    fn an_unknown_schema_operation_or_field_is_refused() {
        for json in [
            r#"{"schema":"nucleus.weight_patch.program.v2","ops":[{"op":"add_scalar","tensor":"a","value":"0x3f000000"}]}"#,
            r#"{"schema":"nucleus.weight_patch.program.v1","ops":[{"op":"scale","tensor":"a","value":"0x3f000000"}]}"#,
            r#"{"schema":"nucleus.weight_patch.program.v1","ops":[{"op":"add_scalar","tensor":"a","value":"0x3f000000","also":1}]}"#,
            r#"{"schema":"nucleus.weight_patch.program.v1","ops":[{"op":"add_scalar","tensor":"a","value":"0x3f000000"}],"also":1}"#,
        ] {
            assert!(
                serde_json::from_str::<PatchProgram>(json).is_err(),
                "{json}"
            );
        }
    }

    #[test]
    fn the_targets_are_readable_without_running_the_program() {
        let program = PatchProgram::new(vec![add("b", 0.5), add("a", 0.5)]).unwrap();
        assert_eq!(
            program.targets().into_iter().collect::<Vec<_>>(),
            ["a", "b"]
        );
    }
}
