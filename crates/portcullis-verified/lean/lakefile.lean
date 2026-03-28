import Lake
open Lake DSL

package «portcullisVerified» where
  name := "portcullisVerified"

require mathlib from git
  "https://github.com/leanprover-community/mathlib4" @ "v4.14.0"

lean_lib «PortcullisVerified» where
  roots := #[`PortcullisVerified.CapabilityLevel, `PortcullisVerified.CapabilityLattice]
