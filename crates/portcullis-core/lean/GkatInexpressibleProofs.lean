import GkatGuardedStringProofs

/-!
# A machine-checked inexpressibility: a single `while b` loop exits only at `¬b`

GKAT expressions correspond to **well-nested** automata (the Kleene theorem for
GKAT). The completeness frontier — and the reason general-`n` existence is open —
is that not every automaton is well-nested: Schmid, Kappé, Kozen and Silva (2021)
show *there exists a GKAT automaton inequivalent to any expression automaton*, and
that the expressible behaviours are exactly those satisfying the **nesting
coequation** (a covariety). Proving that full "no expression at all denotes `L`"
result needs that covariety machinery and is NOT attempted here.

What IS machine-checked here is the **structural heart** of the obstruction, over
the guarded-string model of `GkatGuardedStringProofs`:

  `InLoop_exits_on_not_b` — every guarded string accepted by `e^(b)` ends at an
  atom where `b` is **false**. A `while b` loop can only stop when its guard fails.

From this: a `b`-guarded loop (even composed with a tail, `e^(b)·f`) **cannot**
accept a guarded string all of whose atoms satisfy `b` — it can never exit.
Yet such a string IS expressible (e.g. by `b·p·b`). So:

  `single_b_loop_strictly_weaker` — there is an expressible behaviour that no
  single `b`-guarded while-loop captures.

This is the exit-guard obstruction in miniature, and it is exactly why the
single-state Salomaa solution `e^(b)·f` (which GKAT *does* prove exists, uniquely —
`GkatSyntax.salomaa_solution_exists` / `salomaa_solution_unique`) does not extend to
general expressions: to accept at an atom where the loop's own guard holds, control
must exit on a *different* condition — precisely what a second, mutually-recursive
state provides (`GkatFrontierProofs`, `two_cycle_solvable_of_left_distrib`).

Everything here is machine-checked; the impossibility results use only `[propext]`
(the structural lemma and the expressibility witness use no axioms at all),
`sorryAx`-free.
-/

namespace GkatInexpr

open GkatSyntax GkatGS

variable {A T Atom : Type} (V : T → Atom → Bool)

/-- **The exit-guard obstruction.** Every guarded string accepted by `e^(b)` ends
    at an atom where `b` is false: an `InLoop` derivation terminates only via the
    `exit` constructor, whose side condition is `¬b`. Structural induction on the
    loop proof (`lastAtom` of a `step` is the `lastAtom` of its recursive tail). -/
theorem InLoop_exits_on_not_b {b : BExp T} {P : GS A Atom → Prop} {s : GS A Atom}
    (h : InLoop V b P s) : bval V b (lastAtom s.1 s.2) = false := by
  induction h with
  | exit a hb => exact hb
  | step a l1 rest hb hbody hrec ih => simpa [lastAtom_append] using ih

-- ── A concrete inexpressibility over `Atom = Bool`, `b = prim ()` ────────────

/-- The single primitive test reads the atom: `b` holds exactly at atom `true`. -/
def V0 : Unit → Bool → Bool := fun _ a => a

/-- **`b`-guarded loops can't stay inside `b`.** No loop `e^(b)` (with any tail `f`)
    accepts the string `true --p--> true`: both atoms satisfy `b = prim ()`, so the
    loop can never exit — contradicting `InLoop_exits_on_not_b`. Holds for EVERY
    body `e` and tail `f`. -/
theorem b_loop_cannot_stay_true (e f : Exp Unit Unit) :
    ¬ den V0 (.seq (.wh (.prim ()) e) f) (true, [((), true)]) := by
  rintro ⟨m1, m2, hsplit, hloop, -⟩
  have hexit := InLoop_exits_on_not_b V0 hloop
  have hlast : lastAtom true m1 = true := by
    rcases m1 with _ | ⟨⟨_, x⟩, tl⟩
    · rfl
    · obtain ⟨rfl, rfl, -⟩ : x = true ∧ tl = [] ∧ m2 = [] := by simpa using hsplit
      rfl
  rw [hlast] at hexit
  simp [bval, V0] at hexit

/-- The same string IS expressible — by `b · p · b` (`test`, `act`, `test`): it
    starts at a `b`-atom, does one action, and ends at a `b`-atom. -/
theorem b_true_string_is_expressible :
    den V0 (.seq (.test (.prim ())) (.seq (.act ()) (.test (.prim ()))) : Exp Unit Unit)
      (true, [((), true)]) :=
  ⟨[], [((), true)], rfl, ⟨rfl, rfl⟩, [((), true)], [], rfl, ⟨true, true, rfl⟩, ⟨rfl, rfl⟩⟩

/-- **A single `b`-guarded while-loop is strictly weaker than GKAT expressions.**
    The behaviour of `b·p·b` (an expressible program) is not the behaviour of any
    `e^(b)·f`: the witness `true --p--> true` lies in the former (by
    `b_true_string_is_expressible`) but in none of the latter (by
    `b_loop_cannot_stay_true`). This is the exit-guard obstruction that makes
    general-`n` existence hard: accepting where the loop guard still holds needs a
    second exit condition — mutual recursion, not a single loop. -/
theorem single_b_loop_strictly_weaker (e f : Exp Unit Unit) :
    ¬ (∀ gs : GS Unit Bool,
        den V0 (.seq (.test (.prim ())) (.seq (.act ()) (.test (.prim ()))) : Exp Unit Unit) gs ↔
        den V0 (.seq (.wh (.prim ()) e) f) gs) :=
  fun h => b_loop_cannot_stay_true e f ((h _).mp b_true_string_is_expressible)

#print axioms InLoop_exits_on_not_b
#print axioms single_b_loop_strictly_weaker

end GkatInexpr
