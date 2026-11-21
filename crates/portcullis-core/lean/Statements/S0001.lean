import PortcullisCoreDecide.Funs
import DecidePureProofs

/-!
# S0001: the extracted `should_gate` computes the hand model's answer

`nucleus_ifc_kernel.exposure.should_gate` is the Aeneas extraction of
`crates/nucleus-ifc-kernel/src/exposure.rs::should_gate` (library
`PortcullisCoreDecide`). `DecidePureProofs.should_gate` is the hand-written
model the `decide_pure` theorems are proved over. The claim says the two agree
on every input, so the model's theorems speak about the shipped function.

`toExp` and `toOp` carry the extracted types to the model's: field for field,
and constructor for constructor.

This is an open statement: `claim` is a `def … : Prop`, not a theorem, so
nothing depends on it and the axiom audit is unaffected. It is row `S0001` of
`open-statements.toml` at the repository root; see `Statements/README.md`.
Once the row is `posted`, nothing in this module or in the claim's closure may
change: its export is what the row's `statement_sha256` pins.
-/

namespace Statements.S0001

open Aeneas.Std Result nucleus_ifc_kernel

/-- The extracted exposure set, as the model's. -/
def toExp (e : exposure.ExposureSet) : DecidePureProofs.ExposureSet where
  private_data := e.private_data
  untrusted_content := e.untrusted_content
  exfil_vector := e.exfil_vector

/-- The extracted operation, as the model's. -/
def toOp : ifc_ops.Operation → DecidePureProofs.Operation
  | .ReadFiles => .ReadFiles
  | .WriteFiles => .WriteFiles
  | .EditFiles => .EditFiles
  | .RunBash => .RunBash
  | .GlobSearch => .GlobSearch
  | .GrepSearch => .GrepSearch
  | .WebSearch => .WebSearch
  | .WebFetch => .WebFetch
  | .GitCommit => .GitCommit
  | .GitPush => .GitPush
  | .CreatePr => .CreatePr
  | .ManagePods => .ManagePods
  | .SpawnAgent => .SpawnAgent

/-- The extracted `should_gate` never fails, and returns the model's verdict. -/
def claim : Prop :=
  ∀ (e : exposure.ExposureSet) (op : ifc_ops.Operation),
    exposure.should_gate e op = ok (DecidePureProofs.should_gate (toExp e) (toOp op))

end Statements.S0001
