/-
  K4 SPIKE — governance-monotonicity COMPLETENESS, mathlib-free.

  Faithful model of `nucleus-policy-kernel::{decide, governance_monotone,
  representative_requests}`. The keystone claim: checking `allowed(new) ⊆
  allowed(old)` over the FINITE representative domain decides it over the ENTIRE
  (infinite) request space — a decidable, sound-AND-complete anti-self-weakening
  check. `decide`/`governance_monotone` are String/Vec-heavy (Aeneas's weakest
  case), so this is a mathlib-free MODEL (core Lean only, exportable to the nanoda
  browser checker later), to be pinned to the Rust by exhaustive parity tests.

  COMPLETE: `governance_monotone_iff` proves the check is sound AND complete —
  `monotoneOver … (representativeReqs …) = true ↔ monotoneAll` — with axioms
  `[propext, Quot.sound]` (no `Classical.choice`), zero `sorry`. The chain:
  `decide` factors through the per-rule match vector (`decide_congr`, no axioms) →
  each request field is covered by a representative (`field_cover`, via the
  `Fresh` supply that abstracts "mint a value equalling none of the exacts") →
  the constructed representative lies in the cartesian product → completeness.

  The one honest assumption is `Fresh α` (any finite exact-set has an outside
  value) — exactly what `field_representatives` relies on (mint a fresh String);
  realizable for `String`/`Nat`/any infinite type.

  THE PARITY CONTRACT. This proof is *about the model below*; the guarantee
  transfers to the shipped Rust `nucleus-policy-kernel::{decide,
  governance_monotone, representative_requests}` only insofar as the two agree.
  That pin is the `nucleus-policy-kernel` `tests/model_parity.rs` proptest, which
  transcribes the definitions here — `decideAux`/`decideP`, `escalates`,
  `fieldReps`/`representativeReqs`, `monotoneOver` — declaration-for-declaration
  into an independent Rust oracle and asserts, over random policies/requests,
  that the shipped functions equal it (with a third, existential reading of
  `decide` as the differential angle). Both ends are gated in CI: this file's
  `lake build` + `#print axioms governance_monotone_iff` = `[propext, Quot.sound]`
  in `.github/workflows/portcullis-core-proven-lean.yml`, and the parity proptest
  under the policy-kernel's `cargo test`.
-/

namespace GovernanceCompletenessSpike

variable {α : Type} [DecidableEq α]

inductive Matcher (α : Type) where
  | any
  | exact (a : α)

inductive Effect where
  | permit
  | forbid

structure Rule (α : Type) where
  effect : Effect
  principal : Matcher α
  action : Matcher α
  resource : Matcher α

structure Request (α : Type) where
  principal : α
  action : α
  resource : α

abbrev Policy (α : Type) := List (Rule α)

inductive Decision where
  | allow
  | deny
  deriving DecidableEq

/-- `Exact e` matches iff the field equals `e`; `Any` matches anything. Mirrors
    `Matcher::matches` in the kernel. -/
def matchM : Matcher α → α → Bool
  | .any, _ => true
  | .exact e, x => decide (e = x)

/-- A rule matches iff all three field matchers match. Mirrors `Rule::matches`. -/
def ruleMatches (r : Rule α) (q : Request α) : Bool :=
  matchM r.principal q.principal && matchM r.action q.action && matchM r.resource q.resource

/-- Default-deny fold with Forbid-overrides-Permit (a matching Forbid short-
    circuits to Deny). Mirrors `decide` with its `permitted` accumulator. -/
def decideAux : Policy α → Bool → Request α → Decision
  | [], permitted, _ => match permitted with | true => .allow | false => .deny
  | r :: rs, permitted, q =>
    match ruleMatches r q with
    | true =>
      match r.effect with
      | .forbid => .deny
      | .permit => decideAux rs true q
    | false => decideAux rs permitted q

-- NB: named `decideP`, not `decide`, to avoid shadowing core `decide : Prop → Bool`
-- (used below in `matchM`/`field_cover`/`monotoneOver`).
def decideP (p : Policy α) (q : Request α) : Decision := decideAux p false q

/-- **The crux (proved).** `decideAux` depends on the request only through the
    per-rule match vector: if every rule matches `q` exactly as it matches `q'`,
    the decision is identical — for any accumulator. This is what lets a finite
    transversal of the match-signature decide the property over all requests. -/
theorem decideAux_congr (p : Policy α) (b : Bool) (q q' : Request α)
    (h : ∀ r ∈ p, ruleMatches r q = ruleMatches r q') :
    decideAux p b q = decideAux p b q' := by
  induction p generalizing b with
  | nil => rfl
  | cons r rs ih =>
    have hr : ruleMatches r q = ruleMatches r q' := h r (List.mem_cons_self ..)
    have hrs : ∀ x ∈ rs, ruleMatches x q = ruleMatches x q' :=
      fun x hx => h x (List.mem_cons_of_mem r hx)
    unfold decideAux
    rw [hr]
    cases ruleMatches r q' with
    | false => simpa using ih b hrs
    | true =>
      cases r.effect with
      | forbid => rfl
      | permit => simpa using ih true hrs

/-- **The crux, at the entry point.** `decide` factors through the per-rule match
    vector. -/
theorem decide_congr (p : Policy α) (q q' : Request α)
    (h : ∀ r ∈ p, ruleMatches r q = ruleMatches r q') :
    decideP p q = decideP p q' :=
  decideAux_congr p false q q' h

/-- The governance check over an explicit request list (models the loop in
    `governance_monotone` over `representative_requests`). -/
def escalates (old new : Policy α) (q : Request α) : Prop :=
  decideP new q = Decision.allow ∧ decideP old q = Decision.deny

instance (old new : Policy α) (q : Request α) : Decidable (escalates old new q) := by
  unfold escalates; infer_instance

/-- The finite check: no listed request is an escalation. -/
def monotoneOver (old new : Policy α) (reqs : List (Request α)) : Bool :=
  reqs.all (fun q => decide (¬ escalates old new q))

/-- The property `governance_monotone` is meant to DECIDE, over all requests. -/
def monotoneAll (old new : Policy α) : Prop :=
  ∀ q, ¬ escalates old new q

/-- Soundness of the finite check: if it passes over a request list, no listed
    request escalates. -/
theorem monotoneOver_sound (old new : Policy α) (reqs : List (Request α))
    (hpass : monotoneOver old new reqs = true) :
    ∀ q ∈ reqs, ¬ escalates old new q := by
  intro q hq
  have hb := (List.all_eq_true.mp hpass) q hq
  simpa only [decide_eq_true_eq] using hb

/-! ## The completeness lift — a finite transversal decides the infinite space. -/

/-- A supply of fresh atoms: for any finite list, an element outside it. The Rust
    `field_representatives` mints a value equalling none of the finitely-many
    exacts; this is its honest abstraction (realizable for `String`, `Nat`, any
    infinite type). -/
class Fresh (α : Type) where
  fresh : List α → α
  fresh_not_mem : ∀ l : List α, fresh l ∉ l

/-- The exact atom(s) a single field matcher constrains. -/
def exactsOf : Matcher α → List α
  | .any => []
  | .exact e => [e]

/-- Every exact atom appearing in a field position across a rule list. -/
def fieldExacts (sel : Rule α → Matcher α) : List (Rule α) → List α
  | [] => []
  | r :: rs => exactsOf (sel r) ++ fieldExacts sel rs

/-- The field representatives: every collected exact, plus one fresh value that
    equals none of them. Mirrors `field_representatives`. -/
def fieldReps [Fresh α] (sel : Rule α → Matcher α) (rs : List (Rule α)) : List α :=
  Fresh.fresh (fieldExacts sel rs) :: fieldExacts sel rs

/-- A request is representative (for `old`,`new`) iff each field is a field-rep
    over `old ++ new` — i.e. it is a point of the cartesian product
    `representative_requests` builds. -/
def IsRep [Fresh α] (old new : Policy α) (q : Request α) : Prop :=
  q.principal ∈ fieldReps (·.principal) (old ++ new) ∧
  q.action    ∈ fieldReps (·.action)    (old ++ new) ∧
  q.resource  ∈ fieldReps (·.resource)  (old ++ new)

/-- An exact appearing in a rule's field is among the collected field exacts. -/
theorem exactsOf_subset (sel : Rule α → Matcher α) {r : Rule α} :
    ∀ {rs : List (Rule α)}, r ∈ rs → ∀ e ∈ exactsOf (sel r), e ∈ fieldExacts sel rs := by
  intro rs
  induction rs with
  | nil => intro hr; exact absurd hr (by simp)
  | cons a as ih =>
    intro hr e he
    rcases List.mem_cons.mp hr with h | h
    · exact h ▸ List.mem_append_left _ he
    · exact List.mem_append_right _ (ih h e he)

/-- **Field cover.** Any atom is matched identically (over all collected exacts)
    by some field representative: equal to a collected exact, else the fresh one. -/
theorem field_cover [Fresh α] (sel : Rule α → Matcher α) (rs : List (Rule α)) (x : α) :
    ∃ rx ∈ fieldReps sel rs, ∀ e ∈ fieldExacts sel rs, decide (e = x) = decide (e = rx) := by
  by_cases hx : x ∈ fieldExacts sel rs
  · exact ⟨x, List.mem_cons_of_mem _ hx, fun _ _ => rfl⟩
  · refine ⟨Fresh.fresh (fieldExacts sel rs), by simp [fieldReps], fun e he => ?_⟩
    have hex : ¬ (e = x) := fun h => hx (h ▸ he)
    have hef : ¬ (e = Fresh.fresh (fieldExacts sel rs)) := fun h => Fresh.fresh_not_mem _ (h ▸ he)
    rw [decide_eq_decide]
    exact ⟨fun h => (hex h).elim, fun h => (hef h).elim⟩

/-- A field matcher matches `x` and `rx` alike when the cover holds over its exact. -/
theorem matchM_cover (m : Matcher α) (x rx : α)
    (h : ∀ e ∈ exactsOf m, decide (e = x) = decide (e = rx)) : matchM m x = matchM m rx := by
  cases m with
  | any => rfl
  | exact e => simpa [matchM, exactsOf] using h e (by simp [exactsOf])

/-- **Cover, per rule.** Any request is matched identically by every rule of
    `old ++ new` as its constructed representative is. -/
theorem rep_cover [Fresh α] (old new : Policy α) (q : Request α) :
    ∃ rep, IsRep old new rep ∧ ∀ r ∈ old ++ new, ruleMatches r q = ruleMatches r rep := by
  obtain ⟨rp, hrp_mem, hrp⟩ := field_cover (·.principal) (old ++ new) q.principal
  obtain ⟨ra, hra_mem, hra⟩ := field_cover (·.action) (old ++ new) q.action
  obtain ⟨rr, hrr_mem, hrr⟩ := field_cover (·.resource) (old ++ new) q.resource
  refine ⟨⟨rp, ra, rr⟩, ⟨hrp_mem, hra_mem, hrr_mem⟩, fun r hr => ?_⟩
  unfold ruleMatches
  rw [matchM_cover r.principal q.principal rp (fun e he => hrp e (exactsOf_subset _ hr e he)),
      matchM_cover r.action q.action ra (fun e he => hra e (exactsOf_subset _ hr e he)),
      matchM_cover r.resource q.resource rr (fun e he => hrr e (exactsOf_subset _ hr e he))]

/-- The explicit representative list — the cartesian product, mirroring
    `representative_requests`. -/
def representativeReqs [Fresh α] (old new : Policy α) : List (Request α) :=
  (fieldReps (·.principal) (old ++ new)).flatMap (fun p =>
    (fieldReps (·.action) (old ++ new)).flatMap (fun a =>
      (fieldReps (·.resource) (old ++ new)).map (fun r => ⟨p, a, r⟩)))

theorem mem_representativeReqs [Fresh α] (old new : Policy α) (rep : Request α)
    (h : IsRep old new rep) : rep ∈ representativeReqs old new := by
  obtain ⟨hp, ha, hr⟩ := h
  simp only [representativeReqs, List.mem_flatMap, List.mem_map]
  exact ⟨rep.principal, hp, rep.action, ha, rep.resource, hr, rfl⟩

/-- **K4 — completeness.** Passing `governance_monotone`'s finite check over the
    representative domain DECIDES anti-self-weakening over the ENTIRE request
    space: no escalation exists anywhere. -/
theorem governance_monotone_complete [Fresh α] (old new : Policy α)
    (hpass : monotoneOver old new (representativeReqs old new) = true) :
    monotoneAll old new := by
  intro q hbad
  obtain ⟨rep, hrep, hcov⟩ := rep_cover old new q
  refine monotoneOver_sound old new _ hpass rep (mem_representativeReqs old new rep hrep) ?_
  obtain ⟨hnew, hold⟩ := hbad
  refine ⟨?_, ?_⟩
  · rw [← decide_congr new q rep (fun r hr => hcov r (List.mem_append_right _ hr))]; exact hnew
  · rw [← decide_congr old q rep (fun r hr => hcov r (List.mem_append_left _ hr))]; exact hold

/-- **Soundness** (the easy direction): if no escalation exists anywhere, the
    finite check passes. Together with completeness, `governance_monotone` is a
    decision procedure for `monotoneAll`. -/
theorem governance_monotone_sound [Fresh α] (old new : Policy α)
    (h : monotoneAll old new) : monotoneOver old new (representativeReqs old new) = true := by
  simp only [monotoneOver, List.all_eq_true]
  intro q _
  simpa only [decide_eq_true_eq] using h q

/-- `governance_monotone` decides `monotoneAll` — sound AND complete. -/
theorem governance_monotone_iff [Fresh α] (old new : Policy α) :
    monotoneOver old new (representativeReqs old new) = true ↔ monotoneAll old new :=
  ⟨governance_monotone_complete old new, governance_monotone_sound old new⟩

end GovernanceCompletenessSpike
