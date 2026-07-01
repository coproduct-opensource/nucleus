/-
  K4 SPIKE — governance-monotonicity COMPLETENESS, mathlib-free.

  Faithful model of `nucleus-policy-kernel::{decide, governance_monotone,
  representative_requests}`. The keystone claim: checking `allowed(new) ⊆
  allowed(old)` over the FINITE representative domain decides it over the ENTIRE
  (infinite) request space — a decidable, sound-AND-complete anti-self-weakening
  check. `decide`/`governance_monotone` are String/Vec-heavy (Aeneas's weakest
  case), so this is a mathlib-free MODEL (core Lean only, exportable to the nanoda
  browser checker later), to be pinned to the Rust by exhaustive parity tests.

  This spike proves the load-bearing lemma — `decide` factors through the
  per-rule match vector (hence through the finite exact-signature) — which is the
  mathematically uncertain crux. The representative-cover step (every request
  field equals a collected exact or a fresh value) is a bounded remaining effort.
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

def decide (p : Policy α) (q : Request α) : Decision := decideAux p false q

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
    decide p q = decide p q' :=
  decideAux_congr p false q q' h

/-- The governance check over an explicit request list (models the loop in
    `governance_monotone` over `representative_requests`). -/
def monotoneOver (old new : Policy α) (reqs : List (Request α)) : Bool :=
  reqs.all (fun q => !(decide new q == Decision.allow && decide old q == Decision.deny))

/-- The property `governance_monotone` is meant to DECIDE, over all requests. -/
def monotoneAll (old new : Policy α) : Prop :=
  ∀ q, ¬ (decide new q = Decision.allow ∧ decide old q = Decision.deny)

/-- **Soundness of the finite check (proved):** if the check passes over a
    request list, no escalation exists AT any listed request. (The interesting
    direction — that the *representatives* cover all requests, so this lifts to
    `monotoneAll` — is the bounded remaining step: it needs the field-representative
    cover lemma + a fresh atom, on top of `decide_congr`.) -/
theorem monotoneOver_sound (old new : Policy α) (reqs : List (Request α))
    (hpass : monotoneOver old new reqs = true) :
    ∀ q ∈ reqs, ¬ (decide new q = Decision.allow ∧ decide old q = Decision.deny) := by
  intro q hq hbad
  have := (List.all_eq_true.mp hpass) q hq
  obtain ⟨ha, hd⟩ := hbad
  simp [ha, hd] at this

end GovernanceCompletenessSpike
