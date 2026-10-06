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

/// The most effects one upstream may declare.
pub const MAX_EFFECTS: usize = 64;

/// The most segments one pattern may have.
pub const MAX_PATTERN_SEGMENTS: usize = 32;

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

    /// Validate a registry entry's `kind` and `effects`. The one place an
    /// absent kind is read, as [`UpstreamKind::Api`]: the node's registry and
    /// `nucleus run --egress` both build their table here, so the projection
    /// they compare cannot differ on it.
    ///
    /// # Errors
    /// See [`EffectTableError`].
    pub fn from_parts(
        kind: Option<UpstreamKind>,
        effects: Vec<DeclaredEffect>,
    ) -> Result<Self, EffectTableError> {
        if effects.len() > MAX_EFFECTS {
            return Err(EffectTableError::TooMany(effects.len()));
        }
        let mut parsed: Vec<(&DeclaredEffect, Vec<String>)> = Vec::with_capacity(effects.len());
        for effect in &effects {
            let segments = pattern_segments(&effect.path)
                .ok_or_else(|| EffectTableError::BadPattern(effect.path.clone()))?;
            for (other, other_segments) in &parsed {
                if other.method == effect.method
                    && other.operation != effect.operation
                    && overlap(other_segments, &segments)
                {
                    return Err(EffectTableError::Ambiguous(
                        other.path.clone(),
                        effect.path.clone(),
                    ));
                }
            }
            parsed.push((effect, segments));
        }
        Ok(Self {
            kind: kind.unwrap_or(UpstreamKind::Api),
            effects,
        })
    }

    /// The declared operation for a request, if an effect matches it.
    pub(super) fn declared(&self, method: EgressMethod, path: &str) -> Option<EgressOperation> {
        let request = request_segments(path);
        self.effects
            .iter()
            .filter(|e| e.method == method)
            .find(|e| pattern_segments(&e.path).is_some_and(|pattern| matches(&pattern, &request)))
            .map(|e| e.operation)
    }
}

/// A pattern's segments, lower-cased, or `None` if it is not a pattern.
fn pattern_segments(pattern: &str) -> Option<Vec<String>> {
    let segments: Vec<String> = pattern
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let valid = !segments.is_empty()
        && segments.len() <= MAX_PATTERN_SEGMENTS
        && segments.iter().all(|s| {
            s == "*"
                || (!s.contains(['*', '%', '?', '#', '\\'])
                    && s != ".."
                    && s != "."
                    && s.bytes().all(|b| b.is_ascii_graphic()))
        });
    valid.then_some(segments)
}

/// A request path's segments, percent-decoded to a fixed point and
/// lower-cased, empty segments dropped.
fn request_segments(path: &str) -> Vec<String> {
    super::decoded_lowercase(path)
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn matches(pattern: &[String], request: &[String]) -> bool {
    pattern.len() == request.len() && pattern.iter().zip(request).all(|(p, r)| p == "*" || p == r)
}

/// Whether some path matches both patterns.
fn overlap(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x == "*" || y == "*" || x == y)
}
