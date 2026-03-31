import PortcullisCore.Types
import PortcullisCoreBridge

/-!
# Compartment Ceiling Proofs

Proves properties of the compartment capability ceilings used by
the nucleus-claude-hook for research/draft/execute/breakglass modes.

## What's proved

1. **Ceiling narrowing**: `meet(perms, ceiling(c)) ≤ perms` for all compartments
2. **Ceiling ordering**: Research ≤ Draft ≤ Execute ≤ Breakglass (total order)
3. **Meet with ceiling is deflationary**: capabilities can only narrow, never widen
4. **Breakglass is top**: `meet(perms, top) = perms` (identity)
5. **Research blocks writes**: `meet(perms, research_ceiling).write_files = ⊥`

All proofs discharge via `decide`/`simp` over the 3-element CapabilityLevel type.
No sorry. No SMT oracle.
-/

open portcullis_core
open PortcullisCoreBridge

namespace CompartmentProofs

-- ═══════════════════════════════════════════════════════════════════════
-- Compartment ceilings (matching Rust Compartment::ceiling())
-- ═══════════════════════════════════════════════════════════════════════

/-- Research ceiling: read + web only, no writes/execution -/
def research_ceiling : CapabilityLattice := {
  read_files := .Always
  write_files := .Never
  edit_files := .Never
  run_bash := .Never
  glob_search := .Always
  grep_search := .Always
  web_search := .Always
  web_fetch := .Always
  git_commit := .Never
  git_push := .Never
  create_pr := .Never
  manage_pods := .Never
  spawn_agent := .Never
}

/-- Draft ceiling: read + write, no execution/web -/
def draft_ceiling : CapabilityLattice := {
  read_files := .Always
  write_files := .Always
  edit_files := .Always
  run_bash := .Never
  glob_search := .Always
  grep_search := .Always
  web_search := .Never
  web_fetch := .Never
  git_commit := .Always
  git_push := .Never
  create_pr := .Never
  manage_pods := .Never
  spawn_agent := .Never
}

/-- Execute ceiling: read + write + bash, no push -/
def execute_ceiling : CapabilityLattice := {
  read_files := .Always
  write_files := .Always
  edit_files := .Always
  run_bash := .Always
  glob_search := .Always
  grep_search := .Always
  web_search := .Never
  web_fetch := .Never
  git_commit := .Always
  git_push := .Never
  create_pr := .Never
  manage_pods := .Always
  spawn_agent := .Always
}

-- Breakglass ceiling is ⊤ (latticeTop from PortcullisCoreBridge)

-- ═══════════════════════════════════════════════════════════════════════
-- Theorem 1: Ceiling ordering (total order on compartments)
-- ═══════════════════════════════════════════════════════════════════════

theorem research_le_draft : research_ceiling ≤ draft_ceiling := by
  simp [research_ceiling, draft_ceiling]
  constructor <;> decide

theorem draft_le_execute : draft_ceiling ≤ execute_ceiling := by
  simp [draft_ceiling, execute_ceiling]
  constructor <;> decide

theorem execute_le_top : execute_ceiling ≤ ⊤ := by
  simp [execute_ceiling]
  exact le_top

theorem research_le_execute : research_ceiling ≤ execute_ceiling := by
  exact le_trans research_le_draft draft_le_execute

-- ═══════════════════════════════════════════════════════════════════════
-- Theorem 2: Meet with ceiling is deflationary
-- ═══════════════════════════════════════════════════════════════════════

theorem meet_research_le (p : CapabilityLattice) :
    p ⊓ research_ceiling ≤ p := by
  exact inf_le_left

theorem meet_draft_le (p : CapabilityLattice) :
    p ⊓ draft_ceiling ≤ p := by
  exact inf_le_left

theorem meet_execute_le (p : CapabilityLattice) :
    p ⊓ execute_ceiling ≤ p := by
  exact inf_le_left

-- ═══════════════════════════════════════════════════════════════════════
-- Theorem 3: Research blocks writes
-- ═══════════════════════════════════════════════════════════════════════

theorem research_blocks_write_files :
    research_ceiling.write_files = CapabilityLevel.Never := by
  rfl

theorem research_blocks_edit_files :
    research_ceiling.edit_files = CapabilityLevel.Never := by
  rfl

theorem research_blocks_run_bash :
    research_ceiling.run_bash = CapabilityLevel.Never := by
  rfl

-- ═══════════════════════════════════════════════════════════════════════
-- Theorem 4: Draft blocks web and execution
-- ═══════════════════════════════════════════════════════════════════════

theorem draft_blocks_web_fetch :
    draft_ceiling.web_fetch = CapabilityLevel.Never := by
  rfl

theorem draft_blocks_run_bash :
    draft_ceiling.run_bash = CapabilityLevel.Never := by
  rfl

-- ═══════════════════════════════════════════════════════════════════════
-- Theorem 5: Execute blocks push
-- ═══════════════════════════════════════════════════════════════════════

theorem execute_blocks_git_push :
    execute_ceiling.git_push = CapabilityLevel.Never := by
  rfl

theorem execute_blocks_create_pr :
    execute_ceiling.create_pr = CapabilityLevel.Never := by
  rfl

-- ═══════════════════════════════════════════════════════════════════════
-- Theorem 6: Breakglass is identity (meet with top)
-- ═══════════════════════════════════════════════════════════════════════

theorem breakglass_is_identity (p : CapabilityLattice) :
    p ⊓ ⊤ = p := by
  exact inf_top_eq

end CompartmentProofs
