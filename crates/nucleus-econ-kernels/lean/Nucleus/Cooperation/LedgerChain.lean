/-
  Nucleus / Cooperation / Ledger Chain  (what the hash chain does and does not catch)

  **STATUS: PROVED (0 `sorry`).** No `Mathlib`; core `Lean` only — structural
  induction plus `decide` on closed terms.

  Closes the #2511 half for `verify_chain`
  (`crates/nucleus-creditworthiness/src/ledger.rs`), which was unit-tested only.

  ════════════════════════════════════════════════════════════════════════════
  HONEST-LIMITS BLOCK — read before citing this file.
  ════════════════════════════════════════════════════════════════════════════

  * **The tamper-evidence theorem is CONDITIONAL on an injectivity hypothesis,
    and that hypothesis is FALSE of the real hash.** `entry_hash` is SHA-256
    over canonical bytes: it maps arbitrarily long inputs to 32 bytes, so it is
    not injective — collisions exist, by counting. `head_injective` assumes what
    is really a COLLISION-RESISTANCE assumption (no one can EXHIBIT a collision),
    and no Lean proof can discharge it. What this file proves is that tamper
    evidence follows FROM that assumption and from nothing else — the chain
    construction adds no further gap. Citing it as "the ledger is proved
    tamper-evident" would be an overclaim; the proved statement is "the ledger
    is tamper-evident if SHA-256 is".

  * **There are TWO crypto assumptions, not one, and the second was found by a
    failed proof.** Tamper evidence at fixed length needs `StepInjective`.
    Detecting TRUNCATION needs `NoStepFixpoint` — that a hash step never returns
    its own input — which injectivity does not imply. The first draft of this
    file tried to derive the truncation result from injectivity and could not,
    because the injectivity result is indexed by equal lengths and truncation is
    precisely the unequal case. Both assumptions are named in the signatures
    that use them, so neither can be cited without being seen.

  * **The structural results below are UNCONDITIONAL and need no cryptography.**
    `seqsOk` mirrors `verify_chain`'s `expected_seq` loop exactly. It is where
    the honest surprise is (next clause), and it holds whatever the hash does.

  * **THE FINDING: `seq` contiguity does NOT catch tail truncation.** Dropping
    entries from the END of a chain leaves a chain that is still contiguous from
    0 (`seqsOk_take`, general — not a special case). Dropping one from the
    MIDDLE is caught (`interior_deletion_is_caught`). So `verify_chain` alone
    cannot tell a fresh short chain from a truncated long one, and a server that
    rolled its ledger back would pass every check in that function. What closes
    it is the RETAINED HEAD COMMITMENT — `head_hash_hex` in the accrue response,
    which a caller keeps precisely so a later prefix rewrite is detectable
    (`truncation_is_caught_by_a_retained_head`, and that one needs the
    injectivity hypothesis). The two halves are separated here rather than
    blurred, because the function's own doc comment does not say which check
    does which.

  * **Model, not implementation.** A chain is a list of payloads folded through
    an abstract step; identities, timestamps, `seq` widths and the `saturating_add`
    on the counter are abstracted away. Nothing here is about `redb`, about
    concurrent appends, or about the store's read-compute-write transaction.

  ════════════════════════════════════════════════════════════════════════════
-/

namespace Nucleus.Cooperation.LedgerChain

universe u v

-- ── The hash-linked fold ────────────────────────────────────────────────────

/-- The chain head after folding `payloads` through the hashing step `H`,
    starting from `acc` (`none` at genesis, mirroring `prev_hash: Option`). -/
def chainHead {Payload : Type u} {Hash : Type v}
    (H : Option Hash → Payload → Hash) : Option Hash → List Payload → Option Hash
  | acc, []      => acc
  | acc, p :: ps => chainHead H (some (H acc p)) ps

/-- The collision-resistance assumption, stated as a hypothesis so every result
    that uses it says so in its own signature. See the honest-limits block: this
    is FALSE of SHA-256 as a function and is assumed as an idealisation. -/
def StepInjective {Payload : Type u} {Hash : Type v}
    (H : Option Hash → Payload → Hash) : Prop :=
  ∀ a p b q, H a p = H b q → a = b ∧ p = q

/-- **The chain head determines the whole chain** (under the assumption). Two
    equal-length payload lists folding to the same head from any two starting
    accumulators are the same list, from the same start. -/
theorem head_injective {Payload : Type u} {Hash : Type v}
    {H : Option Hash → Payload → Hash} (hinj : StepInjective H) :
    ∀ (ps qs : List Payload) (a b : Option Hash),
      ps.length = qs.length →
      chainHead H a ps = chainHead H b qs →
      a = b ∧ ps = qs := by
  intro ps
  induction ps with
  | nil =>
    intro qs a b hlen hhead
    cases qs with
    | nil => exact ⟨hhead, rfl⟩
    | cons q qs => exact absurd hlen (by simp)
  | cons p ps ih =>
    intro qs a b hlen hhead
    cases qs with
    | nil => exact absurd hlen (by simp)
    | cons q qs =>
      have hlen' : ps.length = qs.length := by
        simpa using hlen
      have hhead' : chainHead H (some (H a p)) ps = chainHead H (some (H b q)) qs := hhead
      obtain ⟨hacc, hrest⟩ := ih qs (some (H a p)) (some (H b q)) hlen' hhead'
      obtain ⟨ha, hp⟩ := hinj a p b q (Option.some.inj hacc)
      exact ⟨ha, by rw [hp, hrest]⟩

/-- **Tamper evidence** (under the assumption): altering any entry of a chain,
    without changing its length, changes the head. The contrapositive of
    `head_injective`, stated the way a caller uses it. -/
theorem tamper_changes_head {Payload : Type u} {Hash : Type v}
    {H : Option Hash → Payload → Hash} (hinj : StepInjective H)
    (ps qs : List Payload) (a : Option Hash)
    (hlen : ps.length = qs.length) (hne : ps ≠ qs) :
    chainHead H a ps ≠ chainHead H a qs := by
  intro heq
  exact hne (head_injective hinj ps qs a a hlen heq).2

-- ── The structural half: `verify_chain`'s `seq` loop, crypto-free ───────────

/-- `verify_chain`'s `expected_seq` loop, verbatim: entries must carry
    `seq = 0, 1, 2, …` with no gap. Returns `Bool` because the Rust does a
    decidable check, and because it makes the countermodels below `decide`able. -/
def seqsOk : Nat → List Nat → Bool
  | _, []      => true
  | n, s :: rest => (s == n) && seqsOk (n + 1) rest

/-- An honest chain passes. -/
theorem honest_chain_passes : seqsOk 0 [0, 1, 2, 3] = true := by decide

/-- **Deleting an INTERIOR entry is caught** — the gap shows up in the counter.
    This is the case `ChainError::SeqGap` exists for. -/
theorem interior_deletion_is_caught : seqsOk 0 [0, 2, 3] = false := by decide

/-- **Deleting from the TAIL is NOT caught.** A truncated chain is still
    contiguous from 0, so this check passes on it — stated generally, so it
    cannot be dismissed as an artefact of one example. -/
theorem seqsOk_take : ∀ (n : Nat) (l : List Nat) (m : Nat),
    seqsOk m l = true → seqsOk m (l.take n) = true := by
  intro n
  induction n with
  | zero => intro l m _; cases l <;> simp [seqsOk, List.take]
  | succ n ih =>
    intro l m h
    cases l with
    | nil => simpa [List.take] using h
    | cons s rest =>
      simp only [seqsOk, Bool.and_eq_true, beq_iff_eq] at h
      simp only [List.take, seqsOk, Bool.and_eq_true, beq_iff_eq]
      exact ⟨h.1, ih rest (m + 1) h.2⟩

/-- The concrete instance of the gap, for a reader who wants to see it: a
    3-entry chain and its 2-entry truncation both pass. -/
theorem truncation_passes_the_seq_check :
    seqsOk 0 [0, 1, 2] = true ∧ seqsOk 0 [0, 1] = true := by
  constructor <;> decide

/-- Appending one entry hashes the old head. Unconditional, and the shape the
    next result needs. -/
theorem append_head {Payload : Type u} {Hash : Type v}
    {H : Option Hash → Payload → Hash} :
    ∀ (ps : List Payload) (p : Payload) (a : Option Hash),
      chainHead H a (ps ++ [p]) = some (H (chainHead H a ps) p) := by
  intro ps
  induction ps with
  | nil => intro p a; rfl
  | cons q qs ih => intro p a; exact ih p (some (H a q))

/-- A hash step never returns its own input. SEPARATE from `StepInjective` and
    NOT implied by it: an injective `H` may still have `H (some x) p = x`. For
    SHA-256 finding such a fixpoint is believed as hard as finding a collision,
    but "believed as hard as" is not "follows from", so it is assumed by name
    rather than smuggled into the injectivity hypothesis. -/
def NoStepFixpoint {Payload : Type u} {Hash : Type v}
    (H : Option Hash → Payload → Hash) : Prop :=
  ∀ (h : Option Hash) (p : Payload), some (H h p) ≠ h

/-- **What actually closes the truncation gap**: a retained head commitment.
    A chain and its one-entry truncation have different heads, so a caller
    holding the old `head_hash_hex` detects the rollback that `seqsOk` above
    cannot.

    Note which hypothesis this takes. It is `NoStepFixpoint`, NOT
    `StepInjective` — the first draft of this file tried to derive it from
    injectivity via `head_injective` and could not, because `head_injective` is
    indexed by EQUAL LENGTHS and truncation is exactly the unequal case. The
    failed derivation is the reason the fixpoint assumption is named at all. -/
theorem truncation_is_caught_by_a_retained_head {Payload : Type u} {Hash : Type v}
    {H : Option Hash → Payload → Hash} (hfix : NoStepFixpoint H)
    (ps : List Payload) (p : Payload) (a : Option Hash) :
    chainHead H a (ps ++ [p]) ≠ chainHead H a ps := by
  rw [append_head ps p a]
  exact hfix (chainHead H a ps) p

end Nucleus.Cooperation.LedgerChain
