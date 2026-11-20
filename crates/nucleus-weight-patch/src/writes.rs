//! The write set: which tensors actually changed, and whether a proposal said
//! they would.
//!
//! The tensors a patch wrote are the names whose digest differs between the
//! base and the output. That is a measurement of bytes. It is compared with
//! the set the proposal declared, and the answer is one of two things: every
//! write was declared, or here are the writes that were not.
//!
//! A declared set cannot be empty. Elsewhere an empty allow-list has meant
//! "no restriction"; here it has no representation at all.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::digest::{CheckpointIndex, TensorDigest};

/// One tensor whose bytes changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TensorWrite {
    /// The tensor.
    pub name: String,
    /// Its digest in the base checkpoint.
    pub before: TensorDigest,
    /// Its digest in the output checkpoint.
    pub after: TensorDigest,
}

/// Two checkpoints that do not hold the same tensor names.
///
/// A patch changes values. One that adds or removes a tensor has changed what
/// the model is, and that is not a write to be checked against a list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the output adds tensors {added:?} and removes tensors {removed:?}")]
pub struct DiffError {
    /// Names only the output has.
    pub added: BTreeSet<String>,
    /// Names only the base has.
    pub removed: BTreeSet<String>,
}

/// The tensors that differ between a base and an output, measured.
///
/// Minted only by [`diff`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diff {
    writes: BTreeMap<String, (TensorDigest, TensorDigest)>,
}

impl Diff {
    /// The changed tensors, in name order.
    #[must_use]
    pub fn writes(&self) -> Vec<TensorWrite> {
        self.writes
            .iter()
            .map(|(name, (before, after))| TensorWrite {
                name: name.clone(),
                before: *before,
                after: *after,
            })
            .collect()
    }

    /// Whether nothing changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }
}

/// Measures the tensors that differ between `base` and `output`.
///
/// # Errors
///
/// [`DiffError`] if the two do not hold the same tensor names.
pub fn diff(base: &CheckpointIndex, output: &CheckpointIndex) -> Result<Diff, DiffError> {
    let removed: BTreeSet<String> = base
        .iter()
        .filter(|(name, _)| output.get(name).is_none())
        .map(|(name, _)| name.to_owned())
        .collect();
    let added: BTreeSet<String> = output
        .iter()
        .filter(|(name, _)| base.get(name).is_none())
        .map(|(name, _)| name.to_owned())
        .collect();
    if !(added.is_empty() && removed.is_empty()) {
        return Err(DiffError { added, removed });
    }
    let writes = base
        .iter()
        .filter_map(|(name, before)| {
            let after = output.get(name)?;
            (after != before).then(|| (name.to_owned(), (before, after)))
        })
        .collect();
    Ok(Diff { writes })
}

/// A declaration of no tensors, or of one tensor twice.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeclarationError {
    /// No tensor was declared.
    #[error("a declaration names at least one tensor")]
    Empty,
    /// A tensor was declared twice.
    #[error("tensor {tensor:?} is declared twice")]
    Duplicate {
        /// The tensor.
        tensor: String,
    },
}

/// The tensors a proposal says it writes. Never empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
pub struct DeclaredWrites(BTreeSet<String>);

impl DeclaredWrites {
    /// A declaration of `tensors`.
    ///
    /// # Errors
    ///
    /// [`DeclarationError`] for no tensors, or one tensor twice.
    pub fn new<I, S>(tensors: I) -> Result<Self, DeclarationError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut set = BTreeSet::new();
        for tensor in tensors {
            let tensor = tensor.into();
            if set.contains(&tensor) {
                return Err(DeclarationError::Duplicate { tensor });
            }
            set.insert(tensor);
        }
        if set.is_empty() {
            return Err(DeclarationError::Empty);
        }
        Ok(Self(set))
    }

    /// Whether `tensor` is declared.
    #[must_use]
    pub fn contains(&self, tensor: &str) -> bool {
        self.0.contains(tensor)
    }

    /// The declared tensors, in name order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

impl TryFrom<Vec<String>> for DeclaredWrites {
    type Error = DeclarationError;

    fn try_from(tensors: Vec<String>) -> Result<Self, Self::Error> {
        Self::new(tensors)
    }
}

impl From<DeclaredWrites> for Vec<String> {
    fn from(declared: DeclaredWrites) -> Self {
        declared.0.into_iter().collect()
    }
}

/// Evidence that every measured write was declared.
///
/// Minted only by [`check_writes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithinDeclared {
    writes: Vec<TensorWrite>,
    unwritten: BTreeSet<String>,
}

impl WithinDeclared {
    /// The measured writes, in name order.
    #[must_use]
    pub fn writes(&self) -> &[TensorWrite] {
        &self.writes
    }

    /// Declared tensors whose bytes did not change. Not a violation — adding
    /// a small value to a large one can round back to where it started — but
    /// reported, because a reader of the record should not have to infer it.
    #[must_use]
    pub const fn unwritten(&self) -> &BTreeSet<String> {
        &self.unwritten
    }
}

/// Whether the measured writes stayed inside the declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteVerdict {
    /// Every changed tensor was declared.
    Within(WithinDeclared),
    /// At least one changed tensor was not declared.
    Outside {
        /// The changed tensors the declaration does not name. Never empty.
        undeclared: BTreeSet<String>,
        /// Every measured write, declared or not.
        writes: Vec<TensorWrite>,
    },
}

/// Checks measured writes against a declaration.
#[must_use]
pub fn check_writes(measured: &Diff, declared: &DeclaredWrites) -> WriteVerdict {
    let writes = measured.writes();
    let undeclared: BTreeSet<String> = writes
        .iter()
        .filter(|write| !declared.contains(&write.name))
        .map(|write| write.name.clone())
        .collect();
    if !undeclared.is_empty() {
        return WriteVerdict::Outside { undeclared, writes };
    }
    let unwritten = declared
        .iter()
        .filter(|tensor| !measured.writes.contains_key(*tensor))
        .map(str::to_owned)
        .collect();
    WriteVerdict::Within(WithinDeclared { writes, unwritten })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> TensorDigest {
        TensorDigest::from_bytes([byte; 32])
    }

    fn index(tensors: &[(&str, u8)]) -> CheckpointIndex {
        let mut index = CheckpointIndex::empty();
        for (name, byte) in tensors {
            index.insert((*name).to_owned(), digest(*byte)).unwrap();
        }
        index
    }

    #[test]
    fn the_diff_is_the_tensors_whose_digest_changed() {
        let base = index(&[("a", 1), ("b", 2), ("c", 3)]);
        let output = index(&[("a", 1), ("b", 9), ("c", 3)]);
        let measured = diff(&base, &output).unwrap();
        assert_eq!(
            measured.writes(),
            [TensorWrite {
                name: "b".into(),
                before: digest(2),
                after: digest(9)
            }]
        );
        assert!(diff(&base, &base).unwrap().is_empty());
    }

    #[test]
    fn an_added_or_removed_tensor_is_not_a_write() {
        let base = index(&[("a", 1), ("b", 2)]);
        let output = index(&[("a", 1), ("c", 3)]);
        let err = diff(&base, &output).unwrap_err();
        assert_eq!(err.added.into_iter().collect::<Vec<_>>(), ["c"]);
        assert_eq!(err.removed.into_iter().collect::<Vec<_>>(), ["b"]);
    }

    #[test]
    fn an_empty_declaration_does_not_exist() {
        assert_eq!(
            DeclaredWrites::new(Vec::<String>::new()),
            Err(DeclarationError::Empty)
        );
        assert!(serde_json::from_str::<DeclaredWrites>("[]").is_err());
        assert!(serde_json::from_str::<DeclaredWrites>(r#"["a","a"]"#).is_err());
        let declared: DeclaredWrites = serde_json::from_str(r#"["b","a"]"#).unwrap();
        assert_eq!(serde_json::to_string(&declared).unwrap(), r#"["a","b"]"#);
    }

    #[test]
    fn a_declared_write_is_within() {
        let measured = diff(&index(&[("a", 1), ("b", 2)]), &index(&[("a", 1), ("b", 9)])).unwrap();
        let declared = DeclaredWrites::new(["b", "c"]).unwrap();
        match check_writes(&measured, &declared) {
            WriteVerdict::Within(within) => {
                assert_eq!(within.writes().len(), 1);
                assert_eq!(
                    within.unwritten().iter().collect::<Vec<_>>(),
                    ["c"],
                    "declared but unchanged is reported, not refused"
                );
            }
            other @ WriteVerdict::Outside { .. } => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_undeclared_write_is_outside_and_named() {
        let measured = diff(&index(&[("a", 1), ("b", 2)]), &index(&[("a", 8), ("b", 9)])).unwrap();
        let declared = DeclaredWrites::new(["b"]).unwrap();
        match check_writes(&measured, &declared) {
            WriteVerdict::Outside { undeclared, writes } => {
                assert_eq!(undeclared.into_iter().collect::<Vec<_>>(), ["a"]);
                assert_eq!(writes.len(), 2, "the record keeps every write");
            }
            other @ WriteVerdict::Within(_) => panic!("{other:?}"),
        }
    }
}
