/-!
# S0007: a pod is admitted exactly the egress entries both ceilings hold

`Pa.Egress.1` law L3: "a pod egress entry is admitted only if it equals, as a
whole struct, an entry of the registry projection, and, for a pod caller, an
entry of the parent's admitted set". The broker code is
`CredentialedEgressSpec::admitted_by` and `CredentialedEgressSpec::clamp`
(`crates/nucleus-spec/src/lib.rs`) and `PodAuthority::admit_upstreams`
(`crates/nucleus-node/src/pod_authority.rs`).

The claim: `admit_upstreams` admits a request only if every requested entry is
in the registry and, for a pod caller, in the parent's set; it then returns the
request unchanged; when it refuses, the entry it names was requested and is not
granted; and a request whose every entry is granted is admitted.

## A hand model, not an extraction

This claim is about the model below, not about the Rust. Charon's
`--start-from` does not accept inherent methods, so `admitted_by` and `clamp`
cannot be roots of a scoped extraction; and an extraction of the entry type
leaves `EffectTable` as an `axiom … : Type`, an axiom no row may carry. So a
proof of this row proves the model; that the model is the code is checked by
reading the two side by side, and by the Rust tests
`admission_is_whole_struct_equality`,
`a_pod_caller_is_refused_an_upstream_its_parent_lacks` and
`root_and_external_callers_are_refused_what_the_registry_lacks`.

What the model abstracts: an entry is any type with decidable equality. In the
Rust it is `CredentialedEgressSpec`, compared by its derived `PartialEq`; that
the derived equality covers every field ("whole struct") is a fact about the
Rust type, not about this model. The refusal's text and its log line are not
modelled; which entry it names is. That entry is the first one the registry
refused, if any, and only then the first one the parent refused, whatever the
request order: `admit_upstreams`'s doc comment says "the first entry not
granted", which reads as request order and is not what the code does. The
claim says only that the named entry was requested and is not granted.

`claim` is a `def … : Prop`, not a theorem, so nothing depends on it and the
axiom audit is unaffected. It is row `S0007` of `open-statements.toml` at the
repository root; see `Statements/README.md`. Once the row is `posted`, nothing
in this module or in the claim's closure may change.
-/

namespace Statements.S0007

variable {Entry : Type} [DecidableEq Entry]

/-- `CredentialedEgressSpec::admitted_by`: some granted entry equals this one. -/
def admittedBy (entry : Entry) (ceiling : List Entry) : Bool :=
  ceiling.any fun granted => decide (granted = entry)

/-- `CredentialedEgressSpec::clamp`: what the ceiling grants, and what it does
not, each in request order. -/
def clamp (requested ceiling : List Entry) : List Entry × List Entry :=
  requested.partition fun up => admittedBy up ceiling

/-- `PodAuthority::admit_upstreams`. No registry is an empty ceiling; a pod
caller's request is clamped by the registry and then by its parent's set. A
refusal names the first entry of what was dropped. -/
def admitUpstreams (registry : Option (List Entry)) (requested : List Entry)
    (parent : Option (List Entry)) : Except Entry (List Entry) :=
  let first := clamp requested (registry.getD [])
  let second : List Entry × List Entry :=
    match parent with
    | none => first
    | some held =>
      let narrowed := clamp first.1 held
      (narrowed.1, first.2 ++ narrowed.2)
  match second.2 with
  | [] => .ok second.1
  | up :: _ => .error up

/-- An entry the registry holds and, for a pod caller, the parent holds too. -/
def granted (registry : Option (List Entry)) (parent : Option (List Entry))
    (entry : Entry) : Prop :=
  entry ∈ registry.getD [] ∧ ∀ held, parent = some held → entry ∈ held

/-- Admission is exactly "every requested entry is granted". -/
def claim : Prop :=
  ∀ (Entry : Type) [DecidableEq Entry] (registry : Option (List Entry))
    (requested : List Entry) (parent : Option (List Entry)),
    (∀ kept, admitUpstreams registry requested parent = .ok kept →
        kept = requested ∧ ∀ entry ∈ requested, granted registry parent entry) ∧
    (∀ up, admitUpstreams registry requested parent = .error up →
        up ∈ requested ∧ ¬ granted registry parent up) ∧
    ((∀ entry ∈ requested, granted registry parent entry) →
        admitUpstreams registry requested parent = .ok requested)

/-! ## The hypotheses are satisfiable, both ways

Closed instances over `Nat` entries, checked by `decide` on every build. They
add no declaration, so the statement's export is unchanged by them. -/

/-- A pod caller whose request both ceilings hold is admitted as asked. -/
example :
    (match admitUpstreams (some [1, 2, 3]) [2, 1] (some [1, 2]) with
      | .ok kept => kept == [2, 1]
      | .error _ => false) = true := by decide

/-- An entry the registry holds but the parent lacks is refused. -/
example :
    (match admitUpstreams (some [1, 2, 3]) [1, 3] (some [1, 2]) with
      | .ok _ => false
      | .error up => up == 3) = true := by decide

/-- With no registry, a root caller is refused any entry. -/
example :
    (match admitUpstreams none [1] none with
      | .ok _ => false
      | .error up => up == 1) = true := by decide

end Statements.S0007
