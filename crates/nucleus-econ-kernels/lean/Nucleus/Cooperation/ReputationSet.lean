/-
  Nucleus / Cooperation / Reputation Set  (the gossip CRDT's join laws)

  **STATUS: PROVED (0 `sorry`).** No `Mathlib` dependency; core `Lean` only —
  `funext` plus structural case analysis on `Option`. Mirrors the style of
  `Nucleus.Cooperation.BondedDeterrence`.

  Closes the #2511 half for `ReputationSet::join`
  (`crates/nucleus-creditworthiness/src/crdt.rs`), whose semilattice laws were
  property-tested only while the deterrence math they feed is Lean-proved.

  ════════════════════════════════════════════════════════════════════════════
  HONEST-LIMITS BLOCK — read before citing this file.
  ════════════════════════════════════════════════════════════════════════════

  * **The three laws are not equally free.** `join` is LEFT-BIASED union, so
    associativity and idempotence hold UNCONDITIONALLY, and commutativity does
    NOT. It needs `Coherent`: wherever both replicas bind a key, they bind it to
    the same value. `join_not_comm_without_coherence` is the countermodel, so
    the hypothesis is proved load-bearing rather than asserted to be.

  * **`Coherent` is exactly what the Rust panics on.** `crdt.rs`'s `join` panics
    when a `receipt_hash` maps to two different `CreditEvent`s, calling it
    "evidence of a CRDT-invariant violation". This file is what makes that
    sentence precise: the panic is not defensive noise, it is the side condition
    without which convergence is FALSE. A replica that swallowed the conflict
    and picked a side would break commutativity, and two honest replicas
    merging in different orders would disagree about an agent's standing.

  * **What justifies `Coherent` in production is OUTSIDE this file.** It holds
    because the key IS the receipt hash and the value is derived from that
    receipt by recompute — the same receipt recomputes to the same event. That
    is a property of `nucleus-recompute` and of SHA-256, neither of which is
    modelled here. If either failed, these theorems would still be true and the
    system would still be wrong.

  * **The model is the BTreeMap's DENOTATION, not its representation.** A
    `Store` is a total function `K → Option V`. Ordering, iteration order and
    the `[u8; 32]` key type are abstracted away. That is sound for the laws
    proved here (they are about membership) and says NOTHING about the
    canonical-ordering property `ReputationSet::iter` relies on.

  * **Nothing here is about the FOLD.** `reputation_micro` folds the set through
    `CreditFile::from_events`. That the fold is order-insensitive is a separate
    claim, resting on `CreditFile`'s own monoid laws; it is not proved here.

  ════════════════════════════════════════════════════════════════════════════
-/

namespace Nucleus.Cooperation.ReputationSet

universe u v

/-- A replica's event set, as the DENOTATION of the Rust `BTreeMap<[u8;32],
    CreditEvent>`: which keys are bound, and to what. -/
def Store (K : Type u) (V : Type v) : Type (max u v) := K → Option V

/-- The empty set — a fresh identity, reputation 0. -/
def empty {K : Type u} {V : Type v} : Store K V := fun _ => none

/-- Merge, LEFT-BIASED, mirroring `crdt.rs`: the receiver's binding wins, and a
    key only the argument holds is inserted. The Rust reaches the "both bound"
    case and either no-ops (equal) or panics (unequal); left bias is what the
    no-op branch does. -/
def join {K : Type u} {V : Type v} (s t : Store K V) : Store K V :=
  fun k => match s k with
    | some v => some v
    | none   => t k

/-- Two replicas agree wherever they overlap. This is the invariant whose
    violation `crdt.rs` panics on. -/
def Coherent {K : Type u} {V : Type v} (s t : Store K V) : Prop :=
  ∀ k v w, s k = some v → t k = some w → v = w

-- ── The unconditional laws ──────────────────────────────────────────────────

/-- **Idempotent.** Re-merging a replica with itself changes nothing, so a
    duplicated gossip message cannot move standing. -/
theorem join_idem {K : Type u} {V : Type v} (s : Store K V) : join s s = s := by
  funext k
  show (match s k with | some v => some v | none => s k) = s k
  cases s k <;> rfl

/-- **Associative**, with NO coherence hypothesis: left-biased union is
    associative whether or not the replicas agree. -/
theorem join_assoc {K : Type u} {V : Type v} (s t u : Store K V) :
    join (join s t) u = join s (join t u) := by
  funext k
  show (match (match s k with | some v => some v | none => t k) with
        | some v => some v | none => u k)
      = (match s k with
         | some v => some v
         | none => match t k with | some v => some v | none => u k)
  cases s k <;> cases t k <;> rfl

/-- `empty` is a right identity. -/
theorem join_empty {K : Type u} {V : Type v} (s : Store K V) : join s empty = s := by
  funext k
  show (match s k with | some v => some v | none => (empty : Store K V) k) = s k
  cases s k <;> rfl

/-- `empty` is a left identity. -/
theorem empty_join {K : Type u} {V : Type v} (s : Store K V) : join empty s = s := by
  funext k
  rfl

-- ── Commutativity, and the hypothesis it cannot lose ────────────────────────

theorem coherent_symm {K : Type u} {V : Type v} {s t : Store K V}
    (h : Coherent s t) : Coherent t s :=
  fun k v w hv hw => (h k w v hw hv).symm

/-- **Commutative — ONLY under `Coherent`.** Merge order cannot matter, which is
    what makes two honest replicas converge. -/
theorem join_comm {K : Type u} {V : Type v} {s t : Store K V}
    (h : Coherent s t) : join s t = join t s := by
  funext k
  show (match s k with | some v => some v | none => t k)
      = (match t k with | some v => some v | none => s k)
  cases hs : s k with
  | none => cases ht : t k <;> rfl
  | some v =>
    cases ht : t k with
    | none => rfl
    | some w => exact congrArg some (h k v w hs ht)

/-- **The hypothesis is load-bearing.** Two replicas that disagree on one key
    merge to different results in different orders. This is the convergence
    failure `crdt.rs`'s panic refuses to ship, exhibited rather than asserted —
    so `join_comm` cannot be "simplified" by dropping its hypothesis. -/
theorem join_not_comm_without_coherence :
    ∃ (s t : Store Unit Bool), join s t ≠ join t s := by
  refine ⟨fun _ => some true, fun _ => some false, ?_⟩
  intro h
  have : (join (fun _ => some true) (fun _ => some false) : Store Unit Bool) ()
       = (join (fun _ => some false) (fun _ => some true) : Store Unit Bool) () :=
    congrFun h ()
  exact Bool.noConfusion (Option.some.inj this)

/-- Coherence composes: if `u` agrees with both `s` and `t`, it agrees with
    their merge. Without this a three-replica gossip could pass every pairwise
    check and still have no well-defined join. -/
theorem coherent_join {K : Type u} {V : Type v} {s t u : Store K V}
    (hsu : Coherent s u) (htu : Coherent t u) : Coherent (join s t) u := by
  intro k v w hv hw
  show v = w
  cases hs : s k with
  | some x =>
    have hjoin : (join s t) k = some x := by
      show (match s k with | some v => some v | none => t k) = some x
      rw [hs]
    have hxv : x = v := Option.some.inj (hjoin ▸ hv)
    exact hsu k v w (hxv ▸ hs) hw
  | none =>
    have : (join s t) k = t k := by
      show (match s k with | some v => some v | none => t k) = t k
      rw [hs]
    rw [this] at hv
    exact htu k v w hv hw

end Nucleus.Cooperation.ReputationSet
