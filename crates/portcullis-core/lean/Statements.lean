import Statements.S0001

/-!
# Open statements

The root of the `Statements` library. It imports every row's module, so the
proven-tier build compiles each statement (and, once one lands, its proof).
Adding a row adds its import here; nothing in `lakefile.lean` or in a workflow
changes. The convention is in `Statements/README.md`.
-/
