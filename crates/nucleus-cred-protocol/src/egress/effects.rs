//! The operator's effect classification for an upstream (#3229).
//!
//! # Why the operator, and why here
//!
//! What an HTTP call DOES depends on the upstream: a `POST` to a model API is
//! a request for a completion, and a `POST` to a forge's pull-request route
//! opens a pull request. The runtime cannot know that, and must not guess it
//! from a vendor's URL layout. So the operator's registry declares it, per
//! upstream, as a closed table of `(method, path pattern) -> operation`, and
//! the one classifier ([`super::operation_for`]) reads that table on both
//! sides: the guest's tool-proxy, which labels and gates a call, and the
//! host, which recomputes the label and refuses a frame that disagrees
//! (ADR 0007 G-1).
//!
//! The table travels to the guest inside the upstream's projection in the
//! pod spec, and admission compares that projection with the registry's own
//! field for field. A pod therefore holds exactly the operator's table, and
//! a spec that carried a weaker one is refused at admission.
//!
//! # An unclassified write to a forge is refused
//!
//! An upstream declared `kind = "forge"` is one whose writes are effects the
//! policy names. A write that matches no declared effect there is refused,
//! not decided as a fetch (ADR 0007 B: a `_ =>` arm denies). A read, and
//! every call to an `api` upstream that no effect matches, is still a
//! `WebFetch`: what a call to such an upstream already was.
//!
//! # Matching
//!
//! A pattern is a `/`-separated path. Each segment is a literal, compared
//! ignoring ASCII case, or `*`, which matches exactly one non-empty segment.
//! The request path is percent-decoded to a fixed point (as the push
//! classifier decodes it) and empty segments are dropped on both sides, so
//! `repos//o/r/pulls/` and `repos/o/r/pull%73` are both the pull-request
//! route. A path the matcher reads differently from the upstream can only
//! fail to match, and on a forge a write that matches nothing is refused.

use serde::{Deserialize, Serialize};

use super::{EgressMethod, EgressOperation};
use crate::extracted::classify::{self, Effect, TableRefusal};

// The bounds are the deciders', so they are declared there, once.
pub use crate::extracted::classify::{MAX_EFFECTS, MAX_PATTERN_SEGMENTS};

/// What kind of upstream an entry is, for the writes no declared effect
/// classifies.
///
/// No `Default`: an absent kind is read as [`Self::Api`] by
/// [`EffectTable::from_parts`], the one place that decides it, because that
/// is what every upstream was before the kind existed and it grants nothing
/// new (each call is still decided as `WebFetch`, as before).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamKind {
    /// An API whose unclassified calls are network reads (`WebFetch`).
    Api,
    /// A version-control forge: an unclassified write is refused.
    Forge,
}

/// One operator-declared effect: requests with this method whose path
/// matches this pattern are this operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredEffect {
    /// The method, as HTTP spells it.
    pub method: EgressMethod,
    /// The path pattern, under the upstream's base. See the module docs.
    pub path: String,
    /// The operation a matching request is decided as.
    pub operation: EgressOperation,
}

/// Why an effect table was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectTableError {
    /// More than [`MAX_EFFECTS`] effects.
    TooMany(usize),
    /// A pattern that is empty, too long, or has a segment that is neither a
    /// literal nor `*` (a partial glob, a percent-escape, `?`, `#`, `..`).
    BadPattern(String),
    /// Two effects for one method whose patterns overlap and whose
    /// operations differ: which one a request is would depend on order.
    Ambiguous(String, String),
}

impl std::fmt::Display for EffectTableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooMany(n) => write!(f, "{n} effects declared, above the {MAX_EFFECTS} allowed"),
            Self::BadPattern(p) => write!(
                f,
                "effect path {p:?} is not a pattern: segments are literals or `*`, \
                 without `%`, `?`, `#` or `..`"
            ),
            Self::Ambiguous(a, b) => write!(
                f,
                "effect paths {a:?} and {b:?} overlap for one method with different operations"
            ),
        }
    }
}

impl std::error::Error for EffectTableError {}

/// An upstream's validated effect classification.
///
/// Constructible only through [`Self::from_parts`] (deserialisation goes
/// through it too), so a table that exists is one whose patterns parse and
/// whose effects cannot disagree about a request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "EffectTableWire", into = "EffectTableWire")]
pub struct EffectTable {
    kind: UpstreamKind,
    effects: Vec<DeclaredEffect>,
}

/// The table as it crosses the wire, before validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectTableWire {
    kind: UpstreamKind,
    #[serde(default)]
    effects: Vec<DeclaredEffect>,
}

impl TryFrom<EffectTableWire> for EffectTable {
    type Error = EffectTableError;
    fn try_from(wire: EffectTableWire) -> Result<Self, Self::Error> {
        Self::from_parts(Some(wire.kind), wire.effects)
    }
}

impl From<EffectTable> for EffectTableWire {
    fn from(table: EffectTable) -> Self {
        Self {
            kind: table.kind,
            effects: table.effects,
        }
    }
}

impl EffectTable {
    /// The table every upstream had before #3229: an API with no declared
    /// effects, whose calls are decided as `WebFetch` (or `GitPush` for a
    /// push, which no table can weaken).
    #[must_use]
    pub const fn unclassified() -> Self {
        Self {
            kind: UpstreamKind::Api,
            effects: Vec::new(),
        }
    }

    /// Whether this is [`Self::unclassified`]: a spec omits such a table, so
    /// a pod spec that declares no effects serialises as it did before.
    #[must_use]
    pub fn is_unclassified(&self) -> bool {
        self.kind == UpstreamKind::Api && self.effects.is_empty()
    }

    /// The upstream's kind.
    #[must_use]
    pub const fn kind(&self) -> UpstreamKind {
        self.kind
    }

    /// The declared effects, in the operator's order.
    #[must_use]
    pub fn effects(&self) -> &[DeclaredEffect] {
        &self.effects
    }

    /// The effects as the deciders read them (`crate::extracted::classify`).
    pub(crate) fn views(&self) -> Vec<Effect> {
        views(&self.effects)
    }

    /// Validate a registry entry's `kind` and `effects`. The one place an
    /// absent kind is read, as [`UpstreamKind::Api`]: the node's registry and
    /// `nucleus run --egress` both build their table here, so the projection
    /// they compare cannot differ on it.
    ///
    /// Decided by `crate::extracted::classify::from_parts`; this converts the
    /// effects to its view and names the patterns it refused.
    ///
    /// # Errors
    /// See [`EffectTableError`].
    pub fn from_parts(
        kind: Option<UpstreamKind>,
        effects: Vec<DeclaredEffect>,
    ) -> Result<Self, EffectTableError> {
        let path = |i: usize| effects.get(i).map_or_else(String::new, |e| e.path.clone());
        match classify::from_parts(kind, &views(&effects)) {
            Ok(kind) => Ok(Self { kind, effects }),
            Err(TableRefusal::TooMany(count)) => Err(EffectTableError::TooMany(count)),
            Err(TableRefusal::BadPattern(i)) => Err(EffectTableError::BadPattern(path(i))),
            Err(TableRefusal::Ambiguous(earlier, later)) => {
                Err(EffectTableError::Ambiguous(path(earlier), path(later)))
            }
        }
    }

    /// The declared operation for a request, if an effect matches it: the
    /// first, in the operator's order, with this method whose pattern matches
    /// the path. Decided by `crate::extracted::classify::declared`, which
    /// [`super::operation_for`] reaches through `classify::operation_for`.
    #[must_use]
    pub fn declared(&self, method: EgressMethod, path: &str) -> Option<EgressOperation> {
        classify::declared(&self.views(), method, path.as_bytes())
    }
}

/// `effects` as the deciders read them: each pattern's bytes, unparsed.
fn views(effects: &[DeclaredEffect]) -> Vec<Effect> {
    effects
        .iter()
        .map(|e| Effect {
            method: e.method,
            path: e.path.as_bytes().to_vec(),
            operation: e.operation,
        })
        .collect()
}
