/-
  Nucleus / Auctions / Budget Conservation

  **STATUS: PROVED (Weeks 11-12).** The greedy-allocator's budget-conservation
  invariant is now a theorem, not an axiom. Iteration-10 of the substrate-
  build loop replaces the iteration-9 axiom stub with a real structural
  induction over the bid list.

  This file's bytes are the wire contract: `nucleus-market/build.rs` reads
  the SHA-256 and embeds it in every emitted `LineageEdge::Allocation`'s
  `VerifierAttestation.lean_spec_hash`. The hash advances when this file
  advances — trust-service clients can detect "edges pre-2026-05-25 used
  axiom; edges after used theorem."

  # The theorem

  The greedy fold-include-if-fits respects the budget. Formally:

      forall (costs : List Nat) (budget : Nat),
        greedyPack costs budget ≤ budget

  where `greedyPack` walks the cost list left-to-right, including any
  cost whose addition doesn't exceed the budget, accumulating the sum
  of included costs.

  This is the structural invariant the iteration-VCG kernel relies on
  in its budget-bookkeeping. The kernel's `optimal_allocation` sorts
  bids by ratio first, but the budget-conservation property does NOT
  depend on the sort: it holds for ANY traversal order. By proving the
  list-fold version, we get the invariant for free regardless of how
  the kernel chooses to sort.

  # Scope honesty

  This theorem proves ONE thing: the greedy fold respects the budget.
  It does NOT prove:
  - VCG truthfulness (separate property; classical Vickrey 1961 for
    the homogeneous-proposal case; Month 8 will add knapsack-DP
    exact VCG for the heterogeneous case).
  - Individual rationality across all input shapes (depends on
    optimal allocation; greedy is sub-optimal in combinatorial
    knapsack cases).
  - Σ payments ≤ Σ values (depends on IR; same caveat).

  See `crates/nucleus-econ-kernels/src/vcg.rs` module docs for the
  full guarantee matrix.

  # Proof style

  Pure structural induction over `List Nat`. No `Mathlib` dependency.
  No `sorry`. Zero analytic content — just `Nat` arithmetic. Mirrors
  the style of `Nucleus.AnalyzerCorrectness.soundness` (the only other
  load-bearing theorem in this directory).
-/

namespace Nucleus.Auctions.BudgetConservation

/-- The greedy fold-include-if-fits operation.

    Walks the cost list left-to-right. For each cost: if including it
    fits within the remaining budget, accumulate it; otherwise skip.
    Returns the total cost of all included items.

    The accumulator parameter (`acc`) tracks "total cost so far"; the
    `remaining` parameter tracks "budget left." The two invariants
    `acc + remaining = budget` and `acc ≤ budget` are what the
    theorem below proves. -/
def greedyPack : List Nat → Nat → Nat
  | [], _ => 0
  | cost :: rest, remaining =>
      if cost ≤ remaining then
        cost + greedyPack rest (remaining - cost)
      else
        greedyPack rest remaining

/-- **The budget-conservation theorem.** For any cost list and any
    budget, the greedy-pack total is at most the budget.

    Proof: structural induction on the list. The empty case is
    trivial (`0 ≤ budget`). The cons case splits on whether the
    current cost fits in the remaining budget:

    - **Include branch** (`cost ≤ remaining`): by IH, the recursive
      call returns at most `remaining - cost`. Adding `cost` back
      yields at most `cost + (remaining - cost) = remaining ≤ budget`
      (since `remaining ≤ budget` is itself maintained — but here we
      use the structurally weaker fact that the result is bounded by
      the budget threaded through the recursive call).
    - **Skip branch** (`cost > remaining`): the recursive call's
      bound IS the bound we want, by IH.

    The Lean core's `Nat.add_le_of_le_sub'` and friends do the
    arithmetic; no `mathlib` needed.

    # Permutation closure (iteration-11 docstring note)

    The theorem ranges over **all** `costs : List Nat`. In particular,
    for any permutation `costs' = perm costs`, the bound
    `greedyPack costs' budget ≤ budget` follows directly by
    re-instantiating the same theorem at `costs'`. No separate
    induction over permutations is required — the universal
    quantifier already covers every traversal order.

    This is the load-bearing fact the Rust kernel relies on: the
    `run_vcg` allocator in `crates/nucleus-econ-kernels/src/vcg.rs`
    sorts bids by ratio before folding, but that pre-sort step is a
    permutation. The Lean theorem certifies the bound for any
    permutation; the kernel's specific sort is just one instance.

    What permutation closure does NOT give for free:
    - **Optimality**: different traversal orders pack different
      *totals*; greedy is sub-optimal in general (combinatorial
      knapsack). The theorem says ≤ budget; it does NOT say
      "maximally packed."
    - **Winner-set stability**: which items are included depends on
      order; only the budget bound is invariant. -/
theorem greedyPack_le_budget : ∀ (costs : List Nat) (budget : Nat),
    greedyPack costs budget ≤ budget := by
  intro costs
  induction costs with
  | nil =>
      intro budget
      -- `greedyPack [] _ = 0`; `0 ≤ budget` for all `budget`.
      simp [greedyPack]
  | cons cost rest ih =>
      intro budget
      unfold greedyPack
      -- Split on the if-then-else.
      by_cases h : cost ≤ budget
      · -- Include branch: result = cost + greedyPack rest (budget - cost).
        simp [h]
        -- By IH, greedyPack rest (budget - cost) ≤ budget - cost.
        have ih_bound : greedyPack rest (budget - cost) ≤ budget - cost := ih _
        -- So cost + greedyPack rest (budget - cost) ≤ cost + (budget - cost) = budget.
        have : cost + greedyPack rest (budget - cost) ≤ cost + (budget - cost) :=
          Nat.add_le_add_left ih_bound cost
        have cancel : cost + (budget - cost) = budget := Nat.add_sub_cancel' h
        omega
      · -- Skip branch: result = greedyPack rest budget; IH directly.
        simp [h]
        exact ih budget

/-- **Convenience corollary**: a list of `(cost, _payload)` pairs, where
    only the first component matters for budget conservation. This
    mirrors what the Rust kernel actually does — bids carry effective
    values too, but those are irrelevant to the budget-respect property.

    The theorem extracts `.fst` to project costs and reuses the
    base theorem. Useful for downstream Rust-side parity tests that
    want to assert "the kernel's allocator respects the budget"
    against this exact statement. -/
theorem greedyPack_pairs_le_budget
    {α : Type} (xs : List (Nat × α)) (budget : Nat) :
    greedyPack (xs.map Prod.fst) budget ≤ budget := by
  exact greedyPack_le_budget _ _

end Nucleus.Auctions.BudgetConservation
