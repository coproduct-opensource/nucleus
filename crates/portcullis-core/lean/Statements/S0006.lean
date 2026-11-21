/-!
# S0006: an effect table that builds cannot disagree with itself

`Pa.Egress.1` law L1, the build-time clause: "a table whose effects could
disagree about a request (overlapping patterns, one method, different
operations) is refused when it is built". The broker code is
`crates/nucleus-cred-protocol/src/egress/effects.rs`: `EffectTable::from_parts`
refuses an ambiguous table, and `EffectTable::declared` answers with the first
effect, in the operator's order, whose method and pattern match the request.
The claim says that for any table `from_parts` accepts, `declared` answers
with the operation of *every* effect that matches the request, so the answer
does not depend on which matching effect comes first.

## A hand model, not an extraction

This claim is about the model below, not about the Rust. The decisions do not
extract with Charon and Aeneas as written: Aeneas stops on
`core::slice::iter::Iter::find` (a higher-ranked lifetime constraint) and on
`core::str::pattern`, which `declared`, `pattern_segments` and
`decoded_lowercase` use. So a proof of this row proves the model; that the
model is the code is checked by reading the two side by side, and by the Rust
tests `an_effect_table_is_valid_or_refused` and
`a_forge_write_is_what_the_operator_declared_or_refused`.

What the model keeps, and what it abstracts:

* A segment is any type with decidable equality. The Rust segment is a
  lower-cased `String`, and a pattern segment is a literal or `*`; here a
  pattern segment is `some s` (a literal) or `none` (`*`). A literal can never
  be `*` in the Rust (`pattern_segments` refuses a segment containing `*`
  other than `*` itself), so "a literal matches exactly the equal segment" is
  the Rust's `p == "*" || p == r` with the `*` case taken out.
* Splitting, lower-casing and percent-decoding of the path are not modelled:
  the request is already its segment list (`request_segments`).
* Pattern validity is kept as the parts that do not depend on segment text:
  non-empty, and at most `MAX_PATTERN_SEGMENTS` segments. The text checks
  (`%`, `?`, `#`, `\`, `..`, `.`, non-graphic bytes) are per-segment and are
  not modelled.
* `from_parts`'s loop is kept as written: each effect is checked against the
  effects before it, in order, and the first conflict is reported.

L1's other clauses (a push is `GitPush` whatever the table says) and L5 (an
unclassified write to a forge is refused) are not rows. Over a model of
`operation_for` they restate its definition; their content is in the
percent-decoding push test, which is string code Aeneas does not translate.
They wait for an extraction.

`claim` is a `def … : Prop`, not a theorem, so nothing depends on it and the
axiom audit is unaffected. It is row `S0006` of `open-statements.toml` at the
repository root; see `Statements/README.md`. Once the row is `posted`, nothing
in this module or in the claim's closure may change.
-/

namespace Statements.S0006

/-- `EgressMethod`. -/
inductive Method where
  | get
  | post
  deriving DecidableEq

/-- `EgressOperation`. -/
inductive Operation where
  | webFetch
  | gitPush
  | createPr
  deriving DecidableEq

/-- `UpstreamKind`. -/
inductive Kind where
  | api
  | forge
  deriving DecidableEq

/-- A parsed pattern: `some s` is the literal segment `s`, `none` is `*`. -/
abbrev Pattern (Seg : Type) := List (Option Seg)

/-- `DeclaredEffect`, with its path already parsed. -/
structure Effect (Seg : Type) where
  method : Method
  pattern : Pattern Seg
  operation : Operation

/-- `EffectTable`. -/
structure Table (Seg : Type) where
  kind : Kind
  effects : List (Effect Seg)

/-- `EffectTableError`. -/
inductive TableError (Seg : Type) where
  | tooMany (count : Nat)
  | badPattern (pattern : Pattern Seg)
  | ambiguous (first second : Pattern Seg)

/-- `MAX_EFFECTS`. -/
def maxEffects : Nat := 64

/-- `MAX_PATTERN_SEGMENTS`. -/
def maxPatternSegments : Nat := 32

variable {Seg : Type} [DecidableEq Seg]

/-- One pattern segment against one request segment: `*` matches any. -/
def segmentMatches : Option Seg → Seg → Bool
  | none, _ => true
  | some literal, segment => decide (literal = segment)

/-- `matches`: equal length, and every segment matches. -/
def patternMatches (pattern : Pattern Seg) (request : List Seg) : Bool :=
  pattern.length == request.length &&
    (pattern.zip request).all fun pair => segmentMatches pair.1 pair.2

/-- `overlap`: whether some request matches both patterns. -/
def overlap (a b : Pattern Seg) : Bool :=
  a.length == b.length &&
    (a.zip b).all fun pair => pair.1.isNone || pair.2.isNone || decide (pair.1 = pair.2)

/-- The parts of `pattern_segments`'s validity that do not read segment text. -/
def validPattern (pattern : Pattern Seg) : Bool :=
  !pattern.isEmpty && decide (pattern.length ≤ maxPatternSegments)

/-- `from_parts`'s loop: `parsed` holds the effects already accepted, in order. -/
def check (parsed : List (Effect Seg)) : List (Effect Seg) → Option (TableError Seg)
  | [] => none
  | effect :: rest =>
    if !validPattern effect.pattern then
      some (.badPattern effect.pattern)
    else
      match parsed.find? (fun other =>
          decide (other.method = effect.method) &&
            decide (other.operation ≠ effect.operation) &&
            overlap other.pattern effect.pattern) with
      | some other => some (.ambiguous other.pattern effect.pattern)
      | none => check (parsed ++ [effect]) rest

/-- `EffectTable::from_parts`. An absent kind is `api`. -/
def fromParts (kind : Option Kind) (effects : List (Effect Seg)) :
    Except (TableError Seg) (Table Seg) :=
  if effects.length > maxEffects then
    .error (.tooMany effects.length)
  else
    match check [] effects with
    | some refused => .error refused
    | none => .ok { kind := kind.getD .api, effects := effects }

/-- `EffectTable::declared`: the first effect with this method whose pattern
parses and matches the request. -/
def declared (table : Table Seg) (method : Method) (request : List Seg) :
    Option Operation :=
  ((table.effects.filter fun e => decide (e.method = method)).find? fun e =>
      validPattern e.pattern && patternMatches e.pattern request).map (·.operation)

/-- A table `from_parts` builds answers every request with the operation of
every effect that matches it. -/
def claim : Prop :=
  ∀ (Seg : Type) [DecidableEq Seg] (kind : Option Kind) (effects : List (Effect Seg))
    (table : Table Seg),
    fromParts kind effects = .ok table →
      ∀ (method : Method) (request : List Seg) (effect : Effect Seg),
        effect ∈ effects →
          effect.method = method →
            patternMatches effect.pattern request = true →
              declared table method request = some effect.operation

/-! ## The hypotheses are satisfiable, and the build refuses a conflict

Closed instances over `Bool` segments, checked by `decide` on every build. They
add no declaration, so the statement's export is unchanged by them. -/

/-- `repos/*/pulls` as `CreatePr`, and `repos/x/*` as `CreatePr` too. -/
private def agreeing : List (Effect Bool) :=
  [⟨.post, [some true, none, some false], .createPr⟩,
   ⟨.post, [some true, some true, none], .createPr⟩]

/-- The same two patterns, the second now a `WebFetch`. -/
private def disagreeing : List (Effect Bool) :=
  [⟨.post, [some true, none, some false], .createPr⟩,
   ⟨.post, [some true, some true, none], .webFetch⟩]

/-- Overlapping effects that agree build, and a request both match is
`CreatePr` either way round. -/
example :
    (match fromParts none agreeing with
      | .ok table => declared table .post [true, true, false] == some .createPr
      | .error _ => false) = true := by decide

/-- Overlapping effects for one method that disagree are refused. -/
example :
    (match fromParts (some .forge) disagreeing with
      | .ok _ => false
      | .error (.ambiguous _ _) => true
      | .error _ => false) = true := by decide

end Statements.S0006
