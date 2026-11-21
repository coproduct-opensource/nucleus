import Statements.S0001
import Statements.S0006
import Statements.S0007
import Statements.S0008

/-!
# Open statements

The root of the `Statements` library. It imports every row's module, so the
proven-tier build compiles each statement (and, once one lands, its proof).
Adding a row adds its import here; nothing in `lakefile.lean` or in a workflow
changes. The convention is in `Statements/README.md`.
-/
