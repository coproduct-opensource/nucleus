//! Python bindings for the portcullis policy algebra.
//!
//! The only formally verified policy algebra available as a pip package.
//! Lean 4 proofs. Belnap bilattice. Composable combinators.
//!
//! ```python
//! from portcullis import Verdict, all_of, any_of
//!
//! result = Verdict.ALLOW.truth_meet(Verdict.DENY)
//! assert result == Verdict.DENY
//!
//! # Contradiction detection
//! combined = Verdict.ALLOW.info_join(Verdict.DENY)
//! assert combined == Verdict.CONFLICT
//! ```

use pyo3::prelude::*;

use portcullis_core::bilattice::Verdict as RustVerdict;

/// A four-valued policy verdict forming a Belnap bilattice.
///
/// Two orderings:
/// - Truth: Deny < Unknown < Allow
/// - Information: Unknown < {Allow, Deny} < Conflict
///
/// Five operations are functionally complete (Bruni et al., ACM TISSEC).
#[pyclass(eq, hash, frozen)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Operation is permitted.
    #[pyo3(name = "ALLOW")]
    Allow,
    /// Operation is denied.
    #[pyo3(name = "DENY")]
    Deny,
    /// Not enough information to decide.
    #[pyo3(name = "UNKNOWN")]
    Unknown,
    /// Contradictory signals from multiple sources.
    #[pyo3(name = "CONFLICT")]
    Conflict,
}

impl From<Verdict> for RustVerdict {
    fn from(v: Verdict) -> Self {
        match v {
            Verdict::Allow => RustVerdict::Allow,
            Verdict::Deny => RustVerdict::Deny,
            Verdict::Unknown => RustVerdict::Unknown,
            Verdict::Conflict => RustVerdict::Conflict,
        }
    }
}

impl From<RustVerdict> for Verdict {
    fn from(v: RustVerdict) -> Self {
        match v {
            RustVerdict::Allow => Verdict::Allow,
            RustVerdict::Deny => Verdict::Deny,
            RustVerdict::Unknown => Verdict::Unknown,
            RustVerdict::Conflict => Verdict::Conflict,
        }
    }
}

#[pymethods]
impl Verdict {
    /// Truth-meet: most restrictive (AND).
    /// Allow & Deny = Deny. Both must allow.
    fn truth_meet(&self, other: Verdict) -> Verdict {
        let r: RustVerdict = (*self).into();
        r.truth_meet(other.into()).into()
    }

    /// Truth-join: most permissive (OR).
    /// Deny | Allow = Allow. Either may allow.
    fn truth_join(&self, other: Verdict) -> Verdict {
        let r: RustVerdict = (*self).into();
        r.truth_join(other.into()).into()
    }

    /// Negate: flip Allow <-> Deny, preserve Unknown/Conflict.
    fn negate(&self) -> Verdict {
        let r: RustVerdict = (*self).into();
        r.negate().into()
    }

    /// Information-meet: least informative (consensus minimum).
    fn info_meet(&self, other: Verdict) -> Verdict {
        let r: RustVerdict = (*self).into();
        r.info_meet(other.into()).into()
    }

    /// Information-join: most informative (detects contradictions).
    /// Allow ∨_k Deny = Conflict.
    fn info_join(&self, other: Verdict) -> Verdict {
        let r: RustVerdict = (*self).into();
        r.info_join(other.into()).into()
    }

    /// Whether this verdict allows the operation.
    fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow)
    }

    /// Whether this verdict denies the operation.
    fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny)
    }

    /// Whether this verdict represents contradictory signals.
    fn is_conflict(&self) -> bool {
        matches!(self, Verdict::Conflict)
    }

    /// Whether this verdict is decided (Allow or Deny).
    fn is_decided(&self) -> bool {
        matches!(self, Verdict::Allow | Verdict::Deny)
    }

    fn __repr__(&self) -> String {
        format!("Verdict.{self:?}")
    }

    fn __str__(&self) -> String {
        match self {
            Verdict::Allow => "ALLOW".into(),
            Verdict::Deny => "DENY".into(),
            Verdict::Unknown => "UNKNOWN".into(),
            Verdict::Conflict => "CONFLICT".into(),
        }
    }
}

/// The portcullis module — formally verified policy algebra.
#[pymodule]
fn portcullis(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Verdict>()?;
    Ok(())
}
