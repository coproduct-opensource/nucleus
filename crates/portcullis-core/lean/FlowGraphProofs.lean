import FlowProofs

/-!
# FlowGraph Causal DAG Proofs

Proves that label propagation through the causal DAG preserves
information flow invariants. Hand-written Lean models mirroring
`portcullis-core/src/flow.rs` and `portcullis/src/flow_graph.rs`.

No proof holes. No SMT. All proofs fully checked by Lean 4.
-/

namespace FlowGraphProofs
open FlowProofs

-- ═══════════════════════════════════════════════════════════════════════
-- IFC Label (product of the three lattice dimensions)
-- ═══════════════════════════════════════════════════════════════════════

structure IFCLabel where
  conf : ConfLevel
  integ : IntegLevel
  auth : AuthorityLevel
deriving DecidableEq, Repr

def IFCLabel.join (a b : IFCLabel) : IFCLabel :=
  { conf := ConfLevel.join a.conf b.conf,
    integ := IntegLevel.join a.integ b.integ,
    auth := AuthorityLevel.join a.auth b.auth }

-- ═══════════════════════════════════════════════════════════════════════
-- Theorem 1–3: Join monotonicity on each dimension
-- ═══════════════════════════════════════════════════════════════════════

theorem join_integrity_le_left (a b : IFCLabel) :
    (IFCLabel.join a b).integ.toNat ≤ a.integ.toNat := by
  simp [IFCLabel.join, IntegLevel.join]; split <;> omega

theorem join_integrity_le_right (a b : IFCLabel) :
    (IFCLabel.join a b).integ.toNat ≤ b.integ.toNat := by
  simp [IFCLabel.join, IntegLevel.join]; split <;> omega

theorem join_conf_ge_left (a b : IFCLabel) :
    (IFCLabel.join a b).conf.toNat ≥ a.conf.toNat := by
  simp [IFCLabel.join, ConfLevel.join]; split <;> omega

theorem join_conf_ge_right (a b : IFCLabel) :
    (IFCLabel.join a b).conf.toNat ≥ b.conf.toNat := by
  simp [IFCLabel.join, ConfLevel.join]; split <;> omega

theorem join_authority_le_left (a b : IFCLabel) :
    (IFCLabel.join a b).auth.toNat ≤ a.auth.toNat := by
  simp [IFCLabel.join, AuthorityLevel.join]; split <;> omega

theorem join_authority_le_right (a b : IFCLabel) :
    (IFCLabel.join a b).auth.toNat ≤ b.auth.toNat := by
  simp [IFCLabel.join, AuthorityLevel.join]; split <;> omega

-- ═══════════════════════════════════════════════════════════════════════
-- Theorem 4–6: IFCLabel join is a semilattice
-- ═══════════════════════════════════════════════════════════════════════

theorem ifc_join_idempotent (a : IFCLabel) :
    IFCLabel.join a a = a := by
  cases a with | mk c i au =>
  simp [IFCLabel.join]
  exact ⟨conf_join_idempotent c, integ_join_idempotent i, auth_join_idempotent au⟩

theorem ifc_join_comm (a b : IFCLabel) :
    IFCLabel.join a b = IFCLabel.join b a := by
  cases a with | mk ac ai aau =>
  cases b with | mk bc bi bau =>
  simp [IFCLabel.join]
  exact ⟨conf_join_comm ac bc, integ_join_comm ai bi, auth_join_comm aau bau⟩

theorem ifc_join_assoc (a b c : IFCLabel) :
    IFCLabel.join (IFCLabel.join a b) c = IFCLabel.join a (IFCLabel.join b c) := by
  cases a with | mk ac ai aau =>
  cases b with | mk bc bi bau =>
  cases c with | mk cc ci cau =>
  simp [IFCLabel.join]
  exact ⟨conf_join_assoc ac bc cc, integ_join_assoc ai bi ci, auth_join_assoc aau bau cau⟩

-- ═══════════════════════════════════════════════════════════════════════
-- Theorem 7: Adversarial taint is absorbing under join
-- ═══════════════════════════════════════════════════════════════════════

/-- Adversarial joined with any integrity stays Adversarial.
    Once tainted, always tainted — the DAG monotonicity property. -/
theorem adversarial_absorbs (a b : IFCLabel)
    (h : a.integ = .Adversarial) :
    (IFCLabel.join a b).integ = .Adversarial := by
  cases a with | mk ac ai aau =>
  cases b with | mk bc bi bau =>
  simp [IFCLabel.join, IntegLevel.join] at *
  subst h; cases bi <;> decide

/-- NoAuthority joined with any authority stays NoAuthority.
    Web content cannot acquire instruction authority. -/
theorem no_authority_absorbs (a b : IFCLabel)
    (h : a.auth = .NoAuthority) :
    (IFCLabel.join a b).auth = .NoAuthority := by
  cases a with | mk ac ai aau =>
  cases b with | mk bc bi bau =>
  simp [IFCLabel.join, AuthorityLevel.join] at *
  subst h; cases bau <;> decide

/-- Secret joined with any confidentiality stays Secret.
    Private data cannot be downgraded by mixing. -/
theorem secret_absorbs (a b : IFCLabel)
    (h : a.conf = .Secret) :
    (IFCLabel.join a b).conf = .Secret := by
  cases a with | mk ac ai aau =>
  cases b with | mk bc bi bau =>
  simp [IFCLabel.join, ConfLevel.join] at *
  subst h; cases bc <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Theorem 10: The Invariant exploit, end-to-end in the DAG
-- ═══════════════════════════════════════════════════════════════════════

/-- Malicious issue + private repo → plan with Adversarial/NoAuthority.
    This is the causal DAG version of FlowProofs.invariant_exploit_blocked. -/
theorem invariant_exploit_dag_blocked :
    let issue : IFCLabel := ⟨.Public, .Adversarial, .NoAuthority⟩
    let repo : IFCLabel := ⟨.Internal, .Trusted, .Directive⟩
    let intrinsic : IFCLabel := ⟨.Internal, .Trusted, .Directive⟩
    let plan : IFCLabel := [issue, repo].foldl IFCLabel.join intrinsic
    plan.integ = .Adversarial ∧ plan.auth = .NoAuthority ∧ plan.conf = .Internal := by
  native_decide

-- ═══════════════════════════════════════════════════════════════════════
-- Theorem 11: Propagation through multiple tainted sources
-- ═══════════════════════════════════════════════════════════════════════

/-- Even with many trusted parents, a single adversarial parent taints
    the entire propagation chain. -/
theorem single_adversarial_taints_chain :
    let trusted : IFCLabel := ⟨.Internal, .Trusted, .Directive⟩
    let adversarial : IFCLabel := ⟨.Public, .Adversarial, .NoAuthority⟩
    let intrinsic : IFCLabel := ⟨.Internal, .Trusted, .Directive⟩
    let result : IFCLabel := [trusted, trusted, adversarial, trusted].foldl IFCLabel.join intrinsic
    result.integ = .Adversarial ∧ result.auth = .NoAuthority := by
  native_decide

-- ═══════════════════════════════════════════════════════════════════════
-- Theorem 12: Clean propagation preserves trust
-- ═══════════════════════════════════════════════════════════════════════

/-- When all parents are trusted with directive authority, the propagated
    label preserves trust. No false denials for clean chains. -/
theorem clean_chain_preserves_trust :
    let user : IFCLabel := ⟨.Internal, .Trusted, .Directive⟩
    let file : IFCLabel := ⟨.Internal, .Trusted, .Directive⟩
    let intrinsic : IFCLabel := ⟨.Internal, .Trusted, .Directive⟩
    let result : IFCLabel := [user, file].foldl IFCLabel.join intrinsic
    result.integ = .Trusted ∧ result.auth = .Directive := by
  native_decide

end FlowGraphProofs
