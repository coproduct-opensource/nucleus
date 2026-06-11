/-
# The attenuation algebra — generic, machine-checked

Lean counterpart of `src/attenuation.rs` (`Attenuation<L: Lattice>`,
`MeetCap`, `Compose`, `chain_effective_authority`). Where
`DelegationCategoryProofs.lean` proves the *binary* composition laws
for one concrete constraint model (three min-composed fields), this
file proves the laws **generically over any meet-semilattice** and
adds the list-level keystone the Rust tests sample-check:

1. `Attenuation.comp` — deflationary + monotone endomaps are closed
   under composition (the structure-with-proof-fields pattern from
   olog's `AuthFibration.lean`).
2. `meetCap_comp_collapse` / `meetCap_comp_comm` — capping by `a`
   then `b` IS capping by `b ⊓ a`, in either order.
3. `chainAuthority_perm_invariant` — **effective end-of-chain
   authority is independent of the order the caps are folded in**
   (RFC 8693 act-chains / SPIFFE multi-hop: any verifier may fold the
   chain in any order and agree).
4. `applyChain_eq_chainAuthority` — sequentially *applying* the caps
   as attenuations equals the single meet-fold (definitional), so the
   chain replay reduces to one meet — the recompute-reduction shape.

All theorems kernel-checked — no `sorry`.
-/

import Mathlib.Order.Lattice
import Mathlib.Order.Monotone.Basic

set_option autoImplicit false

namespace PortcullisAttenuation

variable {α : Type*} [SemilatticeInf α]

/-- A monotone deflationary endomap on a meet-semilattice: applying it
never grants authority (`defl`) and never inverts the order (`mono`).
Mirrors the Rust trait `attenuation::Attenuation`. -/
structure Attenuation (α : Type*) [SemilatticeInf α] where
  toFun : α → α
  defl : ∀ x, toFun x ≤ x
  mono : Monotone toFun

/-- Composition of attenuations is an attenuation — both laws are
closed under `∘`. Mirrors `attenuation::Compose`. -/
def Attenuation.comp (f g : Attenuation α) : Attenuation α where
  toFun := f.toFun ∘ g.toFun
  defl := fun x => le_trans (f.defl (g.toFun x)) (g.defl x)
  mono := f.mono.comp g.mono

/-- The canonical attenuation: meet with a fixed cap.
Mirrors `attenuation::MeetCap`. -/
def meetCap (c : α) : Attenuation α where
  toFun := fun x => x ⊓ c
  defl := fun _ => inf_le_left
  mono := fun _ _ h => inf_le_inf_right c h

@[simp] theorem meetCap_apply (c x : α) : (meetCap c).toFun x = x ⊓ c := rfl

/-- Capping by `d` then by `c` is one cap by `d ⊓ c`: meet-attenuation
chains collapse to a single cap. -/
theorem meetCap_comp_collapse (c d : α) :
    ((meetCap c).comp (meetCap d)).toFun = (meetCap (d ⊓ c)).toFun := by
  funext x
  simp [Attenuation.comp, inf_assoc]

/-- The order two caps are applied in is irrelevant. -/
theorem meetCap_comp_comm (c d : α) :
    ((meetCap c).comp (meetCap d)).toFun = ((meetCap d).comp (meetCap c)).toFun := by
  funext x
  simp [Attenuation.comp]
  rw [inf_assoc, inf_assoc, inf_comm d c]

/-- Effective authority at the end of a chain of caps: the start
authority met with every cap, left to right. Mirrors
`attenuation::chain_effective_authority`. -/
def chainAuthority (start : α) (caps : List α) : α :=
  caps.foldl (· ⊓ ·) start

@[simp] theorem chainAuthority_nil (start : α) : chainAuthority start [] = start := rfl

@[simp] theorem chainAuthority_cons (start c : α) (caps : List α) :
    chainAuthority start (c :: caps) = chainAuthority (start ⊓ c) caps := rfl

/-- A chain never grants authority: the end-of-chain authority is
below the start. (List-level deflationarity.) -/
theorem chainAuthority_le_start (start : α) (caps : List α) :
    chainAuthority start caps ≤ start := by
  induction caps generalizing start with
  | nil => exact le_refl start
  | cons c cs ih => exact le_trans (ih (start ⊓ c)) inf_le_left

/-- **The keystone**: effective end-of-chain authority is invariant
under permutation of the caps. Any verifier may fold a delegation
chain in any order — association and application order cannot change
the authority it computes. Falls out of meet's commutativity +
associativity, exactly as the Rust module documents. -/
theorem chainAuthority_perm_invariant (start : α) {l₁ l₂ : List α}
    (h : l₁.Perm l₂) :
    chainAuthority start l₁ = chainAuthority start l₂ := by
  induction h generalizing start with
  | nil => rfl
  | cons x _ ih => exact ih (start ⊓ x)
  | swap x y l =>
      show chainAuthority (start ⊓ y ⊓ x) l = chainAuthority (start ⊓ x ⊓ y) l
      rw [inf_right_comm]
  | trans _ _ ih₁ ih₂ => exact (ih₁ start).trans (ih₂ start)

/-- Sequentially *applying* the caps as attenuations is literally the
meet-fold: the chain replay reduces to `chainAuthority`. This is the
recompute-reduction shape — verifying a chain needs one fold, not a
re-enactment of every hop. -/
theorem applyChain_eq_chainAuthority (x : α) (caps : List α) :
    caps.foldl (fun acc c => (meetCap c).toFun acc) x = chainAuthority x caps := rfl

end PortcullisAttenuation
