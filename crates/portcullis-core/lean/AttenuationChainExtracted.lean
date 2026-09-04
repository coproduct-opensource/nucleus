/-
  Attenuation chain — adjacent-swap invariance, proven OVER the Aeneas-EXTRACTED
  `chain_effective_authority` step (not a hand-written mirror).

  **STATUS: VERIFIED.** `lake build AttenuationChainExtracted` (local, 2026-09-04,
  charon 0.1.223 / aeneas d71d2e3, v4.30.0-rc2 Mathlib cache) succeeds with no
  `sorry` anywhere in this file or the generated `PortcullisCoreAttenuation`
  library it depends on. `#print axioms` on all three top-level theorems
  (`foldChain_adjacent_swap`, `foldChain_eq_ok_foldl`, `foldl_adjacent_swap`)
  printed only `[propext, Classical.choice]` (`foldl_adjacent_swap`: no axioms
  at all) — the same trusted Lean/Mathlib kernel set
  `IntegrityNoninterferenceExtracted.lean` cites, not a proof hole
  (`Classical.choice` enters via the `noncomputable def m`'s `.choose`). No
  `sorryAx`, no Aeneas `*External` opaque axiom (the one opaque axiom this
  extraction has, `fold`, is never actually invoked by any proof here — see
  the scope note below).

  The chain:

      crates/portcullis-core/src/attenuation.rs (`chain_effective_authority`)
        --charon (scoped, --start-from chain_effective_authority)-->
          portcullis_core.llbc
        --aeneas -backend lean -split-files-->
          generated-attenuation/PortcullisCoreAttenuation/{Types,Funs}.lean
            (THIS file's deps; the one hand-edit is retargeting Funs.lean's
            self-import, same convention as every other generated-* lib here)
        --(this file)-->  adjacent-swap invariance theorem over THOSE defs.

  # What this proves, precisely

  `AttenuationProofs.lean` already carries a HAND-WRITTEN mirror of
  `chain_effective_authority` and checks reversal-invariance by sample
  (`chain_effective_authority_is_order_independent`, a `#[test]` over four
  concrete `LiteralDelegation` values — evidence, not a universally-quantified
  proof, and over a manually-transcribed Lean model, not the real function).

  This file is strictly stronger on both axes it can be: the per-step
  operation is the REAL Aeneas-extracted body of `chain_effective_authority`'s
  fold closure — `categoryLatticeInst.meet acc cap`, reached from
  `...call_mut` by `rfl`, not retyped — and the theorem is universally
  quantified over every `L` and every well-behaved `category.Lattice L`
  dictionary, not four samples.

  # The one honest gap: `fold` itself is an opaque axiom

  Aeneas could not see into `core::slice::iter::Iter::fold`'s body (Rust
  standard library, outside the scoped extraction), so
  `FunsExternal_Template.lean` gives it a bare TYPE with no equation — an
  axiom with no specification at all. Nothing can be proven about the
  generated `attenuation.chain_effective_authority` definition ITSELF (which
  calls that axiom): from Lean's point of view it could return anything of
  the right type. This is the same shape as
  `IntegrityNoninterferenceExtracted.lean`'s own disclosed gap ("Aeneas does
  not extract the runtime's loop... the fold itself is hand-written Lean") —
  solved the same way: `foldChain` below is a hand-written Lean recursion
  over `List L` (the loop SHAPE is not extracted, same as `irun` there), but
  its single step is proven equal (`call_mut_eq_meet`, by `rfl`) to the
  GENUINELY EXTRACTED closure step, not a hand-transcribed `meet`.

  # Scope: adjacent-swap, not full permutation invariance

  The Rust test (`chain_effective_authority_is_order_independent`) checks
  forward-vs-fully-reversed on one sample. This file proves something that
  IMPLIES reversal invariance and more: swapping any ADJACENT pair of caps
  anywhere in the list leaves the fold result unchanged (`= `, i.e. literally
  the same value, not just `leq`-equivalent). Adjacent transpositions
  generate every permutation of a list (a standard fact, not reproved here),
  so this is the keystone lemma the "any order, same answer" claim rests
  on — full permutation invariance (hence reversal invariance) is a corollary
  this file does not additionally discharge.

  # Hypotheses

  `meet` is required to be TOTAL (never `error`), commutative, and
  associative — exactly `MeetCap`'s three laws from `attenuation.rs`'s module
  doc, restated over the extracted, `Result`-valued `meet` directly (no
  separate hand `Lattice` typeclass assumed). No axiom beyond Aeneas's own
  `Aeneas.Std` primitives and the opaque (unused) `fold` is introduced.
-/

import PortcullisCoreAttenuation.Types
import PortcullisCoreAttenuation.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

namespace AttenuationChainExtracted

/-- The three laws `MeetCap`'s doc comment states, over the extracted,
    `Result`-valued `meet`. -/
structure LawfulOn {L : Type} (inst : portcullis_core.category.Lattice L) : Prop where
  total : ∀ a b : L, ∃ v, inst.meet a b = ok v
  comm : ∀ a b : L, inst.meet a b = inst.meet b a
  assoc : ∀ a b c : L,
    (inst.meet a b >>= fun ab => inst.meet ab c)
      = (inst.meet b c >>= fun bc => inst.meet a bc)

/-- The extracted fold-closure's step, unwrapped: `call_mut inst () (acc, cap)`
    always returns `(t, ())` where `t` is whatever `inst.meet acc cap` gave —
    literally the generated body, `rfl`-transparent (the `def` is not opaque).
    Bridges the closure-object calling convention Aeneas generates to a plain
    binary step. -/
theorem call_mut_eq_meet {L : Type} (inst : portcullis_core.category.Lattice L)
    (acc cap : L) :
    portcullis_core.attenuation.chain_effective_authority.closure.Insts.CoreOpsFunctionFnMutPairLSharedLL.call_mut
        inst () (acc, cap)
      = (do let t ← inst.meet acc cap
            ok (t, ())) := rfl

/-- Hand-written fold shape over `List L` (Aeneas does not extract
    `core::slice::iter::Iter::fold`'s body — see the file header), but each
    step calls the GENUINELY EXTRACTED closure step, not a hand-transcribed
    `meet` (see `foldChain_step_eq_extracted`). -/
def foldChain {L : Type} (inst : portcullis_core.category.Lattice L) :
    L → List L → Result L
  | start, [] => ok start
  | start, cap :: rest => do
      let t ← inst.meet start cap
      foldChain inst t rest

/-- `foldChain`'s one-step unfolding IS the extracted closure's step, not a
    re-implementation of `meet`. -/
theorem foldChain_step_eq_extracted {L : Type} (inst : portcullis_core.category.Lattice L)
    (start cap : L) (rest : List L) :
    foldChain inst start (cap :: rest)
      = (do
          let (t, _) ←
            portcullis_core.attenuation.chain_effective_authority.closure.Insts.CoreOpsFunctionFnMutPairLSharedLL.call_mut
              inst () (start, cap)
          foldChain inst t rest) := by
  simp [foldChain, call_mut_eq_meet]

section LawfulReasoning

variable {L : Type} {inst : portcullis_core.category.Lattice L} (h : LawfulOn inst)

/-- The pure value `meet` returns, extracted from totality by choice. Turns
    the `Result`-monadic laws into equations on plain values. -/
noncomputable def m (a b : L) : L := (h.total a b).choose

theorem meet_eq_ok_m (a b : L) : inst.meet a b = ok (m h a b) :=
  (h.total a b).choose_spec

theorem m_comm (a b : L) : m h a b = m h b a := by
  have hab := meet_eq_ok_m h a b
  have hba := meet_eq_ok_m h b a
  have hc := h.comm a b
  rw [hab, hba] at hc
  exact ok.inj hc

theorem m_assoc (a b c : L) : m h (m h a b) c = m h a (m h b c) := by
  have h1 := h.assoc a b c
  -- h1 : (meet a b >>= fun ab => meet ab c) = (meet b c >>= fun bc => meet a bc)
  rw [meet_eq_ok_m h a b, meet_eq_ok_m h b c] at h1
  simp only [bind_tc_ok] at h1
  -- h1 : meet (m h a b) c = meet a (m h b c)
  rw [meet_eq_ok_m h (m h a b) c, meet_eq_ok_m h a (m h b c)] at h1
  exact ok.inj h1

/-- `foldChain` always succeeds, and its value is the plain `List.foldl` of the
    pure step `m`. This collapses ALL `Result`-monad bookkeeping: the extracted
    (partial, `Result`-valued) fold reduces to a pure `List.foldl`, given
    `LawfulOn`. -/
theorem foldChain_eq_ok_foldl (start : L) (caps : List L) :
    foldChain inst start caps = ok (List.foldl (m h) start caps) := by
  induction caps generalizing start with
  | nil => rfl
  | cons cap rest ih =>
    simp only [foldChain, meet_eq_ok_m h start cap, bind_tc_ok, List.foldl_cons]
    exact ih (m h start cap)

end LawfulReasoning

/-- Pure lemma: for a commutative, associative `f : L → L → L`, swapping two
    ADJACENT elements anywhere in the fold list leaves `List.foldl f start _`
    unchanged. No `Result`, no `meet` — plain list induction. -/
theorem foldl_adjacent_swap {L : Type} (f : L → L → L)
    (fcomm : ∀ a b : L, f a b = f b a) (fassoc : ∀ a b c : L, f (f a b) c = f a (f b c))
    (start : L) (l1 : List L) (x y : L) (l2 : List L) :
    List.foldl f start (l1 ++ x :: y :: l2) = List.foldl f start (l1 ++ y :: x :: l2) := by
  induction l1 generalizing start with
  | nil =>
    simp only [List.nil_append, List.foldl_cons]
    have key : f (f start x) y = f (f start y) x := by
      calc f (f start x) y = f start (f x y) := fassoc start x y
        _ = f start (f y x) := by rw [fcomm x y]
        _ = f (f start y) x := (fassoc start y x).symm
    rw [key]
  | cons hd tl ih =>
    simp only [List.cons_append, List.foldl_cons]
    exact ih (f start hd)

/-- **The keystone.** Swapping two ADJACENT caps anywhere in the list leaves
    the extracted-step fold's result unchanged — the lemma "any order, same
    effective authority" rests on (adjacent transpositions generate every
    permutation of a list). Proven over the REAL extracted per-step operation
    (via `foldChain_eq_ok_foldl` collapsing to `List.foldl (m h)`, then the
    pure `foldl_adjacent_swap`), not a hand mirror. -/
theorem foldChain_adjacent_swap {L : Type} {inst : portcullis_core.category.Lattice L}
    (h : LawfulOn inst) (start : L) (l1 : List L) (x y : L) (l2 : List L) :
    foldChain inst start (l1 ++ x :: y :: l2)
      = foldChain inst start (l1 ++ y :: x :: l2) := by
  rw [foldChain_eq_ok_foldl h, foldChain_eq_ok_foldl h]
  congr 1
  exact foldl_adjacent_swap (m h) (m_comm h) (m_assoc h) start l1 x y l2

end AttenuationChainExtracted
