/-
The `cargo xtask lean-replay --self-test` fixture: writes two one-theorem `.olean`
files that differ in ONE proof term, never by elaborating either.

  LeanReplayProbeSound.claim  : Nat.add 1 1 = 2 := Eq.refl 2   -- the kernel accepts
  LeanReplayProbeForged.claim : Nat.add 1 1 = 2 := Eq.refl 3   -- the kernel rejects

The forged module is the defect `leanchecker` exists for: a constant in an
`.olean` that no kernel ever checked (here, written with `saveModuleData`, which is
what a tampered build artifact or an environment hack amounts to). Writing the
`ModuleData` directly keeps the import closure at `Init` alone, so the `--fresh`
replay of the fixture costs one replay of `Init` and nothing more.

Run as `lake env lean --run forge.lean <out-dir>` inside the tier being probed, so
the fixture is written by, and replayed under, that tier's own toolchain.
-/
import Lean
open Lean

def claimType : Expr :=
  mkApp3 (mkConst ``Eq [Level.one]) (mkConst ``Nat)
    (mkApp2 (mkConst ``Nat.add) (mkNatLit 1) (mkNatLit 1)) (mkNatLit 2)

def claimProof (n : Nat) : Expr :=
  mkApp2 (mkConst ``Eq.refl [Level.one]) (mkConst ``Nat) (mkNatLit n)

def write (dir : System.FilePath) (mod : Name) (proof : Expr) : IO Unit := do
  let name := mod ++ `claim
  let ci := ConstantInfo.thmInfo { name, levelParams := [], type := claimType, value := proof }
  let data : ModuleData := {
    isModule := false
    imports := #[{ module := `Init }]
    constNames := #[name]
    constants := #[ci]
    extraConstNames := #[]
    entries := #[]
  }
  saveModuleData (dir / s!"{mod}.olean") mod data

def main (args : List String) : IO UInt32 := do
  let [dir] := args | do
    IO.eprintln "usage: lean --run forge.lean <out-dir>"
    return 2
  write dir `LeanReplayProbeSound (claimProof 2)
  write dir `LeanReplayProbeForged (claimProof 3)
  return 0
