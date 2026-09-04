/-
  Certificate chain monotonicity — every hop attenuates — proven OVER the
  Aeneas-EXTRACTED per-hop step of `chain_attenuates` (#2451), not a
  hand-written mirror.

  The chain:

      crates/portcullis-core/src/certchain.rs (`chain_attenuates`)
        --charon (scoped, --start-from portcullis_core::certchain::chain_attenuates)-->
          portcullis_core.llbc
        --aeneas -backend lean -split-files-->
          generated-certchain/PortcullisCoreCertChain/{Types,Funs,FunsExternal}.lean
            (THIS file's deps; the one hand-edit is retargeting the
            self-imports, the same convention as every other generated-* lib)
        --(this file)-->  monotonicity theorem over THOSE defs.

  `chain_attenuates` is the monotone-attenuation walk of
  `portcullis::certificate::verify_certificate` (its step 4c,
  `MonotoneViolation`) restated over an abstract `category.Lattice`, so it
  sits inside Aeneas's supported subset. It is bound to the production walk
  by a parity test over real, fully signed certificates
  (`portcullis::certificate::tests::chain_attenuates_agrees_with_verify_certificate`).

  # What this proves

  `chain_attenuates_monotone`: for ANY lattice dictionary whose `clone` is
  the identity (every lawful `Clone` — the extracted step clones the block it
  just checked to carry it forward as the next parent), if the walk returns
  `ok true` on `root` and a chain `l` of any length, then `ChainLeq root l`:
  `leq l[0] root = ok true`, and `leq l[i+1] l[i] = ok true` for every `i`.
  No hop escalates. Unbounded over chain length, by induction on the list —
  genuinely stronger than the Kani DEL harnesses, which are bounded.

  # The one honest gap: `fold` itself is an opaque axiom

  Exactly as `AttenuationChainExtracted.lean` discloses: Aeneas does not see
  into `core::slice::iter::Iter::fold` (standard library, outside the scoped
  extraction), so `FunsExternal.lean` declares it as an axiom with no
  equation, and nothing can be proven about the generated
  `certchain.chain_attenuates` definition ITSELF. `foldAttenuates` below is
  the fold SHAPE, hand-written over `List L`; its single step is proven equal
  by `rfl` (`foldAttenuates_step_eq_extracted`) to the GENUINELY EXTRACTED
  closure body `call_mut` — the `if ok then leq next prev else false` and the
  clone — not a re-typed `leq`. Checked with the pinned toolchain
  (charon 0.1.223 / aeneas d71d2e3): `Iter::fold` is still external there, so
  the pure-core-plus-parity pattern stays the honest one (#2452).

  # Hypotheses

  Only `clone x = ok x`. Nothing about `leq` is assumed — the theorem is
  about what the walk CHECKED, so it holds for any `leq`, lawful or not.
-/

import PortcullisCoreCertChain.Types
import PortcullisCoreCertChain.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

namespace CertChainMonotoneExtracted

abbrev Step {L : Type} (inst : portcullis_core.category.Lattice L) :=
  portcullis_core.certchain.chain_attenuates.closure.Insts.CoreOpsFunctionFnMutPairPairBoolLSharedLPairBoolL.call_mut
    inst ()

/-- The extracted closure's step, unwrapped: literally the generated body,
    `rfl`-transparent (the `def` is not opaque). -/
theorem call_mut_eq {L : Type} (inst : portcullis_core.category.Lattice L)
    (ok1 : Bool) (prev next : L) :
    Step inst ((ok1, prev), next)
      = (do
          let step ← if ok1 then inst.leq next prev else ok false
          let t ← inst.corecloneCloneInst.clone next
          ok ((step, t), ())) := rfl

/-- Hand-written fold shape over `List L` (see the file header); each step
    calls the GENUINELY EXTRACTED closure step. -/
def foldAttenuates {L : Type} (inst : portcullis_core.category.Lattice L) :
    (Bool × L) → List L → Result (Bool × L)
  | acc, [] => ok acc
  | acc, next :: rest => do
      let (acc', _) ← Step inst (acc, next)
      foldAttenuates inst acc' rest

/-- `chain_attenuates` with the fold shape made explicit: `ok true` iff the
    walk over `l` starting from `root` ends with the verdict still `true`. -/
def chainAttenuates {L : Type} (inst : portcullis_core.category.Lattice L)
    (root : L) (l : List L) : Result Bool := do
  let (b, _) ← foldAttenuates inst (true, root) l
  ok b

/-- `foldAttenuates`'s one-step unfolding IS the extracted closure's step. -/
theorem foldAttenuates_step_eq_extracted {L : Type}
    (inst : portcullis_core.category.Lattice L) (acc : Bool × L) (next : L) (rest : List L) :
    foldAttenuates inst acc (next :: rest)
      = (do
          let (acc', _) ← Step inst (acc, next)
          foldAttenuates inst acc' rest) := rfl

/-- Every hop attenuates: the first block is `leq` the root, and each block is
    `leq` the one before it. -/
def ChainLeq {L : Type} (inst : portcullis_core.category.Lattice L) : L → List L → Prop
  | _, [] => True
  | prev, x :: xs => inst.leq x prev = ok true ∧ ChainLeq inst x xs

section

variable {L : Type} {inst : portcullis_core.category.Lattice L}
  (hclone : ∀ x : L, inst.corecloneCloneInst.clone x = ok x)
include hclone

/-- Once a hop has widened, the verdict can never recover: the extracted
    step returns `ok false` without consulting `leq` when `ok1 = false`. -/
theorem foldAttenuates_false_stays_false (prev : L) (l : List L) (b : Bool) (last : L)
    (h : foldAttenuates inst (false, prev) l = ok (b, last)) : b = false := by
  induction l generalizing prev with
  | nil =>
    simp only [foldAttenuates] at h
    exact (Prod.mk.inj (ok.inj h)).1.symm
  | cons x xs ih =>
    rw [foldAttenuates_step_eq_extracted, call_mut_eq] at h
    simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok, hclone x] at h
    exact ih x h

/-- **The theorem.** A walk that returns `true` checked every hop. -/
theorem foldAttenuates_true_implies_chain (prev : L) (l : List L) (last : L)
    (h : foldAttenuates inst (true, prev) l = ok (true, last)) : ChainLeq inst prev l := by
  induction l generalizing prev with
  | nil => trivial
  | cons x xs ih =>
    rw [foldAttenuates_step_eq_extracted, call_mut_eq] at h
    simp only [↓reduceIte] at h
    cases hleq : inst.leq x prev with
    | ok step =>
      rw [hleq] at h
      simp only [bind_tc_ok, hclone x] at h
      cases step with
      | true => exact ⟨hleq, ih x h⟩
      | false =>
        have := foldAttenuates_false_stays_false hclone x xs true last h
        exact absurd this (by decide)
    | fail e => rw [hleq] at h; simp at h
    | div => rw [hleq] at h; simp at h

/-- Stated on the walk itself: `chain_attenuates` answering `true` means no
    hop of the chain escalates, for a chain of any length. -/
theorem chain_attenuates_monotone (root : L) (l : List L)
    (h : chainAttenuates inst root l = ok true) : ChainLeq inst root l := by
  unfold chainAttenuates at h
  cases hf : foldAttenuates inst (true, root) l with
  | ok p =>
    obtain ⟨b, last⟩ := p
    rw [hf] at h
    simp only [bind_tc_ok] at h
    have hb : b = true := ok.inj h
    subst hb
    exact foldAttenuates_true_implies_chain hclone root l last hf
  | fail e => rw [hf] at h; simp at h
  | div => rw [hf] at h; simp at h

end

end CertChainMonotoneExtracted

-- Axiom audit (read by CI from the build log): expected `[propext, Quot.sound]`
-- for the two inductive theorems and NO axioms for the two `rfl` bridges. No
-- `sorryAx`; the opaque `Iter::fold` axiom is never invoked by any proof here.
#print axioms CertChainMonotoneExtracted.chain_attenuates_monotone
#print axioms CertChainMonotoneExtracted.foldAttenuates_true_implies_chain
#print axioms CertChainMonotoneExtracted.foldAttenuates_step_eq_extracted
#print axioms CertChainMonotoneExtracted.call_mut_eq
