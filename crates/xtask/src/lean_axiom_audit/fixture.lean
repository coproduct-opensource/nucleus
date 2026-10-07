/-!
Fixture for `cargo xtask lean-axiom-audit --self-test` (#3302). It belongs to no tier: the
self-test compiles it into a temporary directory, audits it through the same runner and the
same policy as a real tier, and requires exactly the declarations below to be flagged.
-/

axiom probeAxiom : 0 = 0

theorem viaSorry : 1 + 1 = 2 := sorry

theorem viaNative : 2 + 2 = 4 := by native_decide

theorem viaAxiom : 0 = 0 := probeAxiom

theorem clean : 3 + 3 = 6 := rfl

theorem cleanClassical (p : Prop) : p ∨ ¬p := Classical.em p
