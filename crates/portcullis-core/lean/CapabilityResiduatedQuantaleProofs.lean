/-
  Capability is a RESIDUATED QUANTALE — proven OVER the Aeneas-EXTRACTED
  capability functions (from real Rust), not a hand model.

  This is the formal `-core` realization of the Enriched-Reflection model's
  enriching value object `V` (see the spiffy doctrine doc
  "authorization is natural in the execution site"). The capability scalar
  `Never < LowRisk < Always` is a quantale under meet (`⊗ = ∧`, unit `⊤`), and
  meet has a right adjoint `⊸` (the residual / Heyting implication). The
  residuation adjunction

      a ⊗ b ≤ c   ⟺   b ≤ a ⊸ c

  is the defining law: `a ⊸ c` is the OPTIMAL (greatest) attenuation of an
  authority that still keeps `a ⊗ b ≤ c`.

  The extraction chain (reproduced locally on macOS-aarch64 with the prebuilt
  Aeneas nightly-2026.06.10 toolchain — charon 0.1.212):

      crates/nucleus-ifc-kernel/src/extracted/capability_quantale.rs  (real Rust)
        --charon --preset aeneas --start-from capresidual,capmeet,...-->
          nucleus_ifc_kernel.llbc
        --aeneas -backend lean -split-files-->
          generated-cap-quantale/PortcullisCoreCapQuantale/{Types,Funs}.lean
        --(this file)-->  the residuation adjunction over THOSE generated defs.

  The generated functions live in namespace `nucleus_ifc_kernel` and return the
  Aeneas `Result` monad; every theorem is proven in terms of THEM
  (`extracted.capability_quantale.{capmeet,capleq,capresidual,capunit,capbot}`),
  not a hand model. The Rust↔production parity is closed by the exhaustive
  parity tests in `capability_quantale.rs` (the extracted `capmeet`/`capjoin`/
  `capleq` equal the real `CapabilityLevel::{meet,join,leq}`); THIS file closes
  the law-over-extracted gap.
-/

import PortcullisCoreCapQuantale.Types
import PortcullisCoreCapQuantale.Funs

open Aeneas Aeneas.Std Result ControlFlow Error
open nucleus_ifc_kernel.extracted.capability_quantale

-- The case-split reductions unfold the generated `do`/`Result` binds and reduce
-- concrete `U8` comparisons; give them headroom.
set_option maxHeartbeats 1000000

namespace CapabilityResiduatedQuantaleProofs

/-- Short alias for the Aeneas-generated capability enum (from real Rust). -/
abbrev CL := nucleus_ifc_kernel.extracted.capability_quantale.CapLevel

/-- **The residuation adjunction**, over the GENERATED capability functions:
    `a ⊗ b ≤ c  ⟺  b ≤ a ⊸ c` with `⊗ = capmeet`, `⊸ = capresidual`,
    `≤ = capleq`. Both sides are the same `Result Bool` (the boolean *is* the
    iff). 27 concrete triples, each reducing the generated `do`-binds. This is
    the defining law that makes capability a residuated quantale (= Heyting
    algebra) under meet. -/
theorem residuation_adjunction (a b c : CL) :
    (do let m ← capmeet a b; capleq m c) = (do let r ← capresidual a c; capleq b r) := by
  cases a <;> cases b <;> cases c <;> rfl

/-- The residual is **sound** (the counit): `a ⊗ (a ⊸ c) ≤ c`. The greatest `b`
    the adjunction admits is itself admissible. -/
theorem residual_below_ceiling (a c : CL) :
    (do let r ← capresidual a c; let m ← capmeet a r; capleq m c) = ok true := by
  cases a <;> cases c <;> rfl

/-- Quantale unit: `a ⊗ ⊤ = a` (`⊤ = capunit = Always`). -/
theorem capunit_right (a : CL) :
    (do let u ← capunit; capmeet a u) = ok a := by
  cases a <;> rfl

/-- Quantale `⊥`-annihilation: `a ⊗ ⊥ = ⊥` (`⊥ = capbot = Never`). -/
theorem capbot_annihilates (a : CL) :
    (do let z ← capbot; capmeet a z) = capbot := by
  cases a <;> rfl

/-- Meet idempotence: `a ⊗ a = a`. -/
theorem capmeet_idem (a : CL) : capmeet a a = ok a := by
  cases a <;> rfl

end CapabilityResiduatedQuantaleProofs

-- Axiom audit: must be exactly [propext, Classical.choice, Quot.sound] — no
-- `sorryAx`, no Aeneas `*External` opaque axiom — i.e. a genuine proof over the
-- extracted-from-Rust definitions.
#print axioms CapabilityResiduatedQuantaleProofs.residuation_adjunction
