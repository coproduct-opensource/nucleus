/-
  C2 (cross-pod noninterference), increment X-2 — the pod-view relation, mechanized.

  C2 is the North Star clause "*nor those of any other pod*": whatever an agent
  workload does, it cannot learn the secrets of any OTHER pod. Until now C2's only
  evidence was a design document (`docs/cross-pod-view.md`); the corpus had no view
  over STATE, only trace projections. This file turns the design's `podView`
  relation into a kernel-checked two-run theorem.

  Method (from the design doc, after Nickel, OSDI 2018): the view relation is
  UNTRUSTED — a too-coarse relation must FAIL the proof rather than silently pass.
  The relation is squeezed by two unwinding conditions:
    * output-consistency (lower bound): anything a pod reads back through the API
      is DETERMINED by its own view — else the relation is too coarse;
    * local-respect (upper bound): anything another pod's action writes is
      EXCLUDED from the view — else the relation is too fine.

  Scope of THIS increment. The design classifies all 38 `NodeState` fields: 27
  structural (constants, no pod-distinguishing content), 3 secret (never reach a
  pod), 8 shared-mutable (the subject). It mechanizes the ONE shared-mutable field
  introduced first — `pods` — "because it is the only shared-mutable field
  mediated by design" (server-side lineage filter, #2199). The structural 27 fold
  to a shared constant (omitted here); the secret 3 are absent by construction
  (`caller_secret` et al. — a pod cannot name them). The remaining shared-mutable
  surfaces, and the two fields excluded because their code is currently defective
  (`lockdown_tx` → #2203; the identity registry → #2197/#2198/#2204), are NOT
  modelled here and are named in the ledger note as the reason C2 stays NOT-YET.

  Mathlib-free by design (pure `List`/`Nat`), so it kernel-checks fast and carries
  the clean `[propext, Classical.choice, Quot.sound]`-or-fewer axiom profile the
  proven-tier gate requires.
-/

namespace PodCrossView

/-- A pod identifier. `0` is the node/root (parent of top-level pods). -/
abbrev PodId := Nat

/-- Opaque per-pod secret content. Abstract on purpose: the theorem must hold for
    ARBITRARY values, so a pod's secret is an uninterpreted `Nat` the view relation
    never inspects across a lineage boundary. -/
abbrev Label := Nat

/-- A pod on the shared substrate: its id, the id of the pod that created it
    (its `parent`; `0` = node-created top-level), and its own secret content. -/
structure Pod where
  id : PodId
  parent : PodId
  secret : Label
deriving DecidableEq, Repr

/-- `ownedBy p q` — pod `q` is in `p`'s lineage view: `q` is `p` itself, or a
    child `p` created. This is the server-side filter's predicate (`q.parent = p ∨
    q = p`), verbatim from `docs/cross-pod-view.md`. -/
def ownedBy (p : PodId) (q : Pod) : Bool := q.parent == p || q.id == p

/-- The shared substrate, restricted to the one shared-mutable field this
    increment mechanizes. See the header for why the other 37 fields are folded,
    absent, or deferred. -/
structure HostState where
  pods : List Pod
deriving Repr

/-- What a pod observes of the shared substrate. The design's `Observation` has
    three fields (`ownPods`, `ownMaterials`, `ownEvents`); this increment
    mechanizes `ownPods`, the projection over `pods`. -/
structure Observation where
  ownPods : List Pod
deriving DecidableEq, Repr

/-- The view relation, verbatim from `docs/cross-pod-view.md`: a pod sees exactly
    its own lineage-filtered slice of `pods`, and nothing of any other pod. -/
def podView (p : PodId) (σ : HostState) : Observation :=
  { ownPods := σ.pods.filter (ownedBy p) }

/-- The mediated transition on the shared surface: the node creates a pod. -/
def createPod (child : Pod) (σ : HostState) : HostState :=
  { σ with pods := child :: σ.pods }

/-! ## The two unwinding conditions -/

/-- **Output-consistency (lower bound).** A pod's view is DETERMINED by its own
    lineage slice of `pods`: two states that agree on `p`'s owned pods give `p`
    the same observation, whatever any other pod holds. If the relation dropped a
    field a pod can read back, this would be unprovable. -/
theorem output_consistency (p : PodId) (σ₁ σ₂ : HostState)
    (h : σ₁.pods.filter (ownedBy p) = σ₂.pods.filter (ownedBy p)) :
    podView p σ₁ = podView p σ₂ := by
  simp only [podView, h]

/-- **Local-respect (upper bound).** Another pod's write to `pods` — creating a
    pod that is neither `A` nor `A`'s child — is EXCLUDED from `A`'s view. This is
    the theorem with teeth: it is what makes the lineage filter load-bearing. -/
theorem local_respect (A : PodId) (σ : HostState) (child : Pod)
    (hpar : child.parent ≠ A) (hid : child.id ≠ A) :
    podView A (createPod child σ) = podView A σ := by
  have ho : ownedBy A child = false := by
    unfold ownedBy
    have h1 : (child.parent == A) = false := beq_eq_false_iff_ne.mpr hpar
    have h2 : (child.id == A) = false := beq_eq_false_iff_ne.mpr hid
    rw [h1, h2]; rfl
  simp [podView, createPod, ho]

/-! ## Cross-pod noninterference (the two-run payoff) -/

/-- **Cross-pod noninterference.** Pod `A`'s observable is independent of every
    other pod's content: two host states that agree on `A`'s owned pods yield the
    same `podView A`, no matter how their other pods (and those pods' secrets)
    differ. A genuine two-run theorem over state; its non-vacuity is pinned by the
    witnesses below (two states that DO differ in another pod's secret, same view). -/
theorem cross_pod_noninterference (A : PodId) (σ₁ σ₂ : HostState)
    (h : σ₁.pods.filter (ownedBy A) = σ₂.pods.filter (ownedBy A)) :
    podView A σ₁ = podView A σ₂ :=
  output_consistency A σ₁ σ₂ h

/-! ## Non-vacuity — the separating witnesses

If the model were vacuous (view constant, or another pod's write leaking in),
these would be false. They pin that the view does real work AND that the NI
theorem has content. All are closed by `decide` over concrete `Nat`s. -/

/-- A itself (node-created), and one of A's own children. -/
def podA : Pod := { id := 1, parent := 0, secret := 100 }
def podAchild : Pod := { id := 3, parent := 1, secret := 111 }
/-- Pod B (a sibling of A, also node-created), carried at two different secrets. -/
def podB_lo : Pod := { id := 2, parent := 0, secret := 0 }
def podB_hi : Pod := { id := 2, parent := 0, secret := 999 }
/-- A child B created. -/
def podBchild : Pod := { id := 4, parent := 2, secret := 222 }

/-- **Secret-blind (positive).** Two states differing ONLY in another pod (B)'s
    secret give A the SAME view — B's secret does not move A's observable. -/
example :
    podView 1 { pods := [podA, podB_lo] } = podView 1 { pods := [podA, podB_hi] } := by
  decide

/-- **Non-triviality.** A creating A's OWN child DOES change A's view, so the
    relation is not the vacuous constant that would make NI trivially true. -/
example :
    podView 1 (createPod podAchild { pods := [podA] }) ≠ podView 1 { pods := [podA] } := by
  decide

/-- **Local-respect has teeth.** A pod B created is provably ABSENT from A's view. -/
example :
    podBchild ∉ (podView 1 (createPod podBchild { pods := [podA] })).ownPods := by
  decide

/-! ## The coarse-relation-fails guardrail (Nickel discipline, executable)

The whole point of an untrusted view relation is that WEAKENING it must break the
proof, not silently pass. Here is that made concrete: a `podView` with the lineage
filter DROPPED admits another pod's write into A's view, so `local_respect` is
FALSE for it. Shipping a too-coarse relation is therefore a proof failure. -/

/-- The deliberately-coarsened relation: every pod visible to everyone. -/
def podViewCoarse (_p : PodId) (σ : HostState) : Observation := { ownPods := σ.pods }

/-- **Coarse-relation-fails.** Under `podViewCoarse`, B's write (creating B's
    child) DOES change A's view — i.e. `local_respect` does not hold for it. So the
    lineage filter is not decoration: remove it and the unwinding condition breaks. -/
example :
    podViewCoarse 1 (createPod podBchild { pods := [podA] }) ≠ podViewCoarse 1 { pods := [podA] } := by
  decide

end PodCrossView
