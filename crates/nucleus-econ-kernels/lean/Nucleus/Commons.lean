/-
  Nucleus / Commons  (no-skim conservation of externality→commons routing)

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: `Nat` + `omega` + list induction.
  Closes gap **G2a** — the commons routing was tested but not proven.

  Mirrors `nucleus-econ-kernels::commons::route_to_commons`: the Pigouvian pool is
  split across shares (basis points summing to 10_000) by flooring each share, then
  the integer-division **dust** is assigned to the first share so the allocations
  sum to EXACTLY the pool — nothing is skimmed or lost. This is the auditable
  "watch the money fund the fix" property.

  The single nonlinear step (`Σ (pool * bᵢ) = pool * Σ bᵢ`) is discharged by
  `Nat.mul_add` (list distributivity), NOT omega; everything else is omega over
  division by the literal 10_000.
-/

namespace Nucleus.Commons

/-- Per-share floored allocations: `floor(pool * bpsᵢ / 10000)`, mirroring the Rust
    `(pool * s.bps) / COMMONS_BPS_SCALE`. -/
def floorAllocs (pool : Nat) (bps : List Nat) : List Nat :=
  bps.map (fun b => pool * b / 10000)

/-- The routed allocations: the floors, with the dust `pool - Σfloors` assigned to
    the first share (matching `route_to_commons`). Empty shares → empty (the Rust
    rejects empty shares upstream). -/
def routed (pool : Nat) (bps : List Nat) : List Nat :=
  match floorAllocs pool bps with
  | [] => []
  | a :: rest => (a + (pool - (a :: rest).sum)) :: rest

/-- **List distributivity** (the one nonlinear step): `Σ (pool * bᵢ) = pool * Σ bᵢ`. -/
theorem sum_map_mul (pool : Nat) (bps : List Nat) :
    (bps.map (fun b => pool * b)).sum = pool * bps.sum := by
  induction bps with
  | nil => simp
  | cons b rest ih => simp [List.map_cons, List.sum_cons, ih, Nat.mul_add]

/-- **Sum of floors ≤ floor of sum**: `Σ (xᵢ / 10000) ≤ (Σ xᵢ) / 10000`. -/
theorem sum_div_le (xs : List Nat) :
    (xs.map (fun x => x / 10000)).sum ≤ xs.sum / 10000 := by
  induction xs with
  | nil => simp
  | cons x rest ih =>
      simp only [List.map_cons, List.sum_cons]
      omega

/-- **Floors never exceed the pool** when the basis points sum to 10_000. -/
theorem floorAllocs_sum_le (pool : Nat) (bps : List Nat) (hsum : bps.sum = 10000) :
    (floorAllocs pool bps).sum ≤ pool := by
  unfold floorAllocs
  have hmap :
      (bps.map (fun b => pool * b / 10000))
        = ((bps.map (fun b => pool * b)).map (fun x => x / 10000)) := by
    simp [List.map_map, Function.comp]
  rw [hmap]
  have hle := sum_div_le (bps.map (fun b => pool * b))
  rw [sum_map_mul] at hle
  -- hle : … ≤ pool * bps.sum / 10000 ; with Σbps = 10000, pool*10000/10000 = pool.
  have : pool * bps.sum / 10000 = pool := by rw [hsum]; omega
  omega

/-- **G2a — no-skim conservation (PROVED).** The routed allocations sum to EXACTLY
    the pool: dust to the first share makes the split exact, so no externality
    revenue is skimmed or lost. Requires the basis points to sum to 10_000 and the
    share list to be non-empty (both enforced by `route_to_commons`). -/
theorem routed_conserves (pool : Nat) (bps : List Nat)
    (hsum : bps.sum = 10000) (hne : bps ≠ []) :
    (routed pool bps).sum = pool := by
  have hle := floorAllocs_sum_le pool bps hsum
  -- floorAllocs is non-empty because bps is.
  unfold routed
  cases hfa : floorAllocs pool bps with
  | nil =>
      exfalso
      apply hne
      have : bps.map (fun b => pool * b / 10000) = [] := hfa
      simpa [floorAllocs] using this
  | cons a rest =>
      simp only [List.sum_cons]
      -- (a + (pool - (a::rest).sum)) + rest.sum = pool, since (a::rest).sum ≤ pool.
      rw [hfa] at hle
      simp only [List.sum_cons] at hle
      omega

end Nucleus.Commons
