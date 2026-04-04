-- Curated subset of Aeneas-generated functions for verification.
--
-- Extracted from the full Funs.lean (which has trait impls that don't
-- compile under Lean 4.28 due to API changes in Ord/PartialOrd fields).
-- These are the lattice operations we verify: meet, join, implies,
-- complement, leq. The function bodies are UNMODIFIED from Aeneas output.
import Aeneas
import PortcullisCore.Types
import PortcullisCore.FunsExternal
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option maxHeartbeats 1000000

namespace portcullis_core

/-- [portcullis_core::{portcullis_core::CapabilityLevel}::meet]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 58:4-60:5
    Visibility: public -/
def CapabilityLevel.meet
  (self : CapabilityLevel) (other : CapabilityLevel) :
  Result CapabilityLevel
  := do
  let b ←
    CapabilityLevel.Insts.CoreCmpPartialOrdCapabilityLevel.le self other
  if b
  then ok self
  else ok other

/-- [portcullis_core::{portcullis_core::CapabilityLevel}::join]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 63:4-65:5
    Visibility: public -/
def CapabilityLevel.join
  (self : CapabilityLevel) (other : CapabilityLevel) :
  Result CapabilityLevel
  := do
  let b ←
    CapabilityLevel.Insts.CoreCmpPartialOrdCapabilityLevel.ge self other
  if b
  then ok self
  else ok other

/-- [portcullis_core::{portcullis_core::CapabilityLevel}::implies]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 70:4-76:5
    Visibility: public -/
def CapabilityLevel.implies
  (self : CapabilityLevel) (other : CapabilityLevel) :
  Result CapabilityLevel
  := do
  let b ←
    CapabilityLevel.Insts.CoreCmpPartialOrdCapabilityLevel.le self other
  if b
  then ok CapabilityLevel.Always
  else ok other

/-- [portcullis_core::{portcullis_core::CapabilityLevel}::complement]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 79:4-81:5
    Visibility: public -/
def CapabilityLevel.complement
  (self : CapabilityLevel) : Result CapabilityLevel := do
  CapabilityLevel.implies self CapabilityLevel.Never

/-- [portcullis_core::{portcullis_core::CapabilityLevel}::leq]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 84:4-86:5
    Visibility: public -/
def CapabilityLevel.leq
  (self : CapabilityLevel) (other : CapabilityLevel) : Result Bool := do
  CapabilityLevel.Insts.CoreCmpPartialOrdCapabilityLevel.le self other

-- ═══════════════════════════════════════════════════════════════════════
-- Product lattice operations (extracted from Aeneas-generated Funs.lean)
-- Function bodies are UNMODIFIED from Aeneas output.
-- ═══════════════════════════════════════════════════════════════════════

/-- [portcullis_core::{portcullis_core::CapabilityLattice}::bottom]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 134:4-149:5
    Visibility: public -/
def CapabilityLattice.bottom : Result CapabilityLattice := do
  ok
    {
      read_files := CapabilityLevel.Never,
      write_files := CapabilityLevel.Never,
      edit_files := CapabilityLevel.Never,
      run_bash := CapabilityLevel.Never,
      glob_search := CapabilityLevel.Never,
      grep_search := CapabilityLevel.Never,
      web_search := CapabilityLevel.Never,
      web_fetch := CapabilityLevel.Never,
      git_commit := CapabilityLevel.Never,
      git_push := CapabilityLevel.Never,
      create_pr := CapabilityLevel.Never,
      manage_pods := CapabilityLevel.Never,
      spawn_agent := CapabilityLevel.Never
    }

/-- [portcullis_core::{portcullis_core::CapabilityLattice}::top]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 152:4-167:5
    Visibility: public -/
def CapabilityLattice.top : Result CapabilityLattice := do
  ok
    {
      read_files := CapabilityLevel.Always,
      write_files := CapabilityLevel.Always,
      edit_files := CapabilityLevel.Always,
      run_bash := CapabilityLevel.Always,
      glob_search := CapabilityLevel.Always,
      grep_search := CapabilityLevel.Always,
      web_search := CapabilityLevel.Always,
      web_fetch := CapabilityLevel.Always,
      git_commit := CapabilityLevel.Always,
      git_push := CapabilityLevel.Always,
      create_pr := CapabilityLevel.Always,
      manage_pods := CapabilityLevel.Always,
      spawn_agent := CapabilityLevel.Always
    }

/-- [portcullis_core::{portcullis_core::CapabilityLattice}::meet]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 170:4-185:5
    Visibility: public -/
def CapabilityLattice.meet
  (self : CapabilityLattice) (other : CapabilityLattice) :
  Result CapabilityLattice
  := do
  let cl ← CapabilityLevel.meet self.read_files other.read_files
  let cl1 ← CapabilityLevel.meet self.write_files other.write_files
  let cl2 ← CapabilityLevel.meet self.edit_files other.edit_files
  let cl3 ← CapabilityLevel.meet self.run_bash other.run_bash
  let cl4 ← CapabilityLevel.meet self.glob_search other.glob_search
  let cl5 ← CapabilityLevel.meet self.grep_search other.grep_search
  let cl6 ← CapabilityLevel.meet self.web_search other.web_search
  let cl7 ← CapabilityLevel.meet self.web_fetch other.web_fetch
  let cl8 ← CapabilityLevel.meet self.git_commit other.git_commit
  let cl9 ← CapabilityLevel.meet self.git_push other.git_push
  let cl10 ← CapabilityLevel.meet self.create_pr other.create_pr
  let cl11 ← CapabilityLevel.meet self.manage_pods other.manage_pods
  let cl12 ← CapabilityLevel.meet self.spawn_agent other.spawn_agent
  ok
    {
      read_files := cl,
      write_files := cl1,
      edit_files := cl2,
      run_bash := cl3,
      glob_search := cl4,
      grep_search := cl5,
      web_search := cl6,
      web_fetch := cl7,
      git_commit := cl8,
      git_push := cl9,
      create_pr := cl10,
      manage_pods := cl11,
      spawn_agent := cl12
    }

/-- [portcullis_core::{portcullis_core::CapabilityLattice}::join]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 188:4-203:5
    Visibility: public -/
def CapabilityLattice.join
  (self : CapabilityLattice) (other : CapabilityLattice) :
  Result CapabilityLattice
  := do
  let cl ← CapabilityLevel.join self.read_files other.read_files
  let cl1 ← CapabilityLevel.join self.write_files other.write_files
  let cl2 ← CapabilityLevel.join self.edit_files other.edit_files
  let cl3 ← CapabilityLevel.join self.run_bash other.run_bash
  let cl4 ← CapabilityLevel.join self.glob_search other.glob_search
  let cl5 ← CapabilityLevel.join self.grep_search other.grep_search
  let cl6 ← CapabilityLevel.join self.web_search other.web_search
  let cl7 ← CapabilityLevel.join self.web_fetch other.web_fetch
  let cl8 ← CapabilityLevel.join self.git_commit other.git_commit
  let cl9 ← CapabilityLevel.join self.git_push other.git_push
  let cl10 ← CapabilityLevel.join self.create_pr other.create_pr
  let cl11 ← CapabilityLevel.join self.manage_pods other.manage_pods
  let cl12 ← CapabilityLevel.join self.spawn_agent other.spawn_agent
  ok
    {
      read_files := cl,
      write_files := cl1,
      edit_files := cl2,
      run_bash := cl3,
      glob_search := cl4,
      grep_search := cl5,
      web_search := cl6,
      web_fetch := cl7,
      git_commit := cl8,
      git_push := cl9,
      create_pr := cl10,
      manage_pods := cl11,
      spawn_agent := cl12
    }

/-- [portcullis_core::{portcullis_core::CapabilityLattice}::leq]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 206:4-219:5
    Visibility: public -/
def CapabilityLattice.leq
  (self : CapabilityLattice) (other : CapabilityLattice) : Result Bool := do
  let b ← CapabilityLevel.leq self.read_files other.read_files
  if b
  then
    let b1 ← CapabilityLevel.leq self.write_files other.write_files
    if b1
    then
      let b2 ← CapabilityLevel.leq self.edit_files other.edit_files
      if b2
      then
        let b3 ← CapabilityLevel.leq self.run_bash other.run_bash
        if b3
        then
          let b4 ← CapabilityLevel.leq self.glob_search other.glob_search
          if b4
          then
            let b5 ← CapabilityLevel.leq self.grep_search other.grep_search
            if b5
            then
              let b6 ← CapabilityLevel.leq self.web_search other.web_search
              if b6
              then
                let b7 ← CapabilityLevel.leq self.web_fetch other.web_fetch
                if b7
                then
                  let b8 ←
                    CapabilityLevel.leq self.git_commit other.git_commit
                  if b8
                  then
                    let b9 ← CapabilityLevel.leq self.git_push other.git_push
                    if b9
                    then
                      let b10 ←
                        CapabilityLevel.leq self.create_pr other.create_pr
                      if b10
                      then
                        let b11 ←
                          CapabilityLevel.leq self.manage_pods other.manage_pods
                        if b11
                        then
                          CapabilityLevel.leq self.spawn_agent other.spawn_agent
                        else ok false
                      else ok false
                    else ok false
                  else ok false
                else ok false
              else ok false
            else ok false
          else ok false
        else ok false
      else ok false
    else ok false
  else ok false

/-- [portcullis_core::{portcullis_core::CapabilityLattice}::implies]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 222:4-237:5
    Visibility: public -/
def CapabilityLattice.implies
  (self : CapabilityLattice) (other : CapabilityLattice) :
  Result CapabilityLattice
  := do
  let cl ← CapabilityLevel.implies self.read_files other.read_files
  let cl1 ← CapabilityLevel.implies self.write_files other.write_files
  let cl2 ← CapabilityLevel.implies self.edit_files other.edit_files
  let cl3 ← CapabilityLevel.implies self.run_bash other.run_bash
  let cl4 ← CapabilityLevel.implies self.glob_search other.glob_search
  let cl5 ← CapabilityLevel.implies self.grep_search other.grep_search
  let cl6 ← CapabilityLevel.implies self.web_search other.web_search
  let cl7 ← CapabilityLevel.implies self.web_fetch other.web_fetch
  let cl8 ← CapabilityLevel.implies self.git_commit other.git_commit
  let cl9 ← CapabilityLevel.implies self.git_push other.git_push
  let cl10 ← CapabilityLevel.implies self.create_pr other.create_pr
  let cl11 ← CapabilityLevel.implies self.manage_pods other.manage_pods
  let cl12 ← CapabilityLevel.implies self.spawn_agent other.spawn_agent
  ok
    {
      read_files := cl,
      write_files := cl1,
      edit_files := cl2,
      run_bash := cl3,
      glob_search := cl4,
      grep_search := cl5,
      web_search := cl6,
      web_fetch := cl7,
      git_commit := cl8,
      git_push := cl9,
      create_pr := cl10,
      manage_pods := cl11,
      spawn_agent := cl12
    }

end portcullis_core
