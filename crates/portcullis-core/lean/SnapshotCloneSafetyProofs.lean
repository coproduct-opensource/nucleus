/-!
# Snapshot clone-safety — the classification is disjoint, the guard is sound, and
# unsafety is fail-closed (a proof, lifting the Rust test-gates #2300/#2301)

The runtime refuses to snapshot a microVM as a *reusable base* if its kernel
command line carries per-pod secret material — otherwise every clone restored
from that base would inherit the same secret (`nucleus-node/src/snapshot.rs`).
Safety rests on a two-class partition of the `nucleus.*` cmdline keys:
per-pod-secret (never bake) vs shared-config (safe to bake, every clone should
share it), and the decision function `snapshot_safety` fails closed on the
*presence* of any per-pod key.

This file lifts that classification logic from Rust TEST-gates to Lean theorems:

- `partition_disjoint` — the two classes never overlap (lifts #2300's
  `the_two_key_classifications_are_disjoint`, and because the domain is the whole
  finite `CmdKey`, it is a COMPLETE proof, not a sample).
- `safe_iff_no_per_pod` — the guard is sound AND complete: it returns
  `SafeToClone` exactly when no per-pod key is present.
- `unsafe_persists_under_superset` — **fail-closed / anti-laundering**: once a
  cmdline is unsafe, no additional keys can launder it back to `SafeToClone`.
  This is the clone analog of the session-taint ratchet.

## Boundary (PROVED / TESTED / NOT-YET)
- PROVED here: the classification is disjoint, the guard is sound+complete, and
  unsafety is monotone (fail-closed).
- TESTED (Rust #2301, `no_pod_cmdline_carries_any_per_pod_secret`): the REAL
  emitter `FirecrackerConfig::from_spec` never emits a per-pod key — over the two
  identity states of a canonical spec, not ∀ spec.
- NOT-YET: the ∀-spec emitter property as a proof (the emitter is String-typed,
  not Aeneas-extractable as-is); wiring the guard to a production snapshot-create
  call site (no Firecracker snapshot API is called yet).

The `CmdKey` model is bound to the production key sets by the exhaustive parity
test `lean_model_classification_matches_production` in `snapshot.rs` (the #2299
discipline). Mathlib-free; `#print axioms` audited at the end.
-/

namespace SnapshotCloneSafety

/-- Faithful model of the classified `nucleus.*` cmdline keys (snapshot.rs:112 /
    :137). The first nine are `PER_POD_SECRET_KEYS`, the next eight are
    `SHARED_CONFIG_KEYS`; `otherPublic` stands for any unclassified base key
    (`console=`, `init=`, …). -/
inductive CmdKey where
  -- PER_POD_SECRET_KEYS (snapshot.rs:112)
  | approvalSecret | authSecret | sandboxToken
  | taskTokenHex | taskTokenIssuer | taskTokenNonce
  | awsAccessKeyId | awsSecretAccessKey | awsSessionToken
  -- SHARED_CONFIG_KEYS (snapshot.rs:137)
  | approvalPubkeys | auditS3Bucket | auditS3Endpoint | auditS3Prefix | auditS3Region
  | awsDefaultRegion | workloadApiPort | net
  -- any other (unclassified) base key
  | otherPublic
  deriving DecidableEq, Repr

/-- Per-pod secret keys — must never be baked into a snapshot base. -/
def CmdKey.isPerPodSecret : CmdKey → Bool
  | .approvalSecret | .authSecret | .sandboxToken
  | .taskTokenHex | .taskTokenIssuer | .taskTokenNonce
  | .awsAccessKeyId | .awsSecretAccessKey | .awsSessionToken => true
  | _ => false

/-- Per-node / per-fleet shared config — safe to bake (every clone shares it). -/
def CmdKey.isSharedConfig : CmdKey → Bool
  | .approvalPubkeys | .auditS3Bucket | .auditS3Endpoint | .auditS3Prefix | .auditS3Region
  | .awsDefaultRegion | .workloadApiPort | .net => true
  | _ => false

/-- Model of `SnapshotSafety` (snapshot.rs:155). -/
inductive Safety where
  | safeToClone
  | wouldDuplicateSecret (key : CmdKey)
  deriving DecidableEq, Repr

/-- Model of `snapshot_safety` (snapshot.rs:193): the FIRST per-pod-secret key
    present makes the base unclonable; otherwise `SafeToClone`. Fails closed on
    the PRESENCE of a key. -/
def snapshotSafety : List CmdKey → Safety
  | [] => .safeToClone
  | k :: rest => if k.isPerPodSecret then .wouldDuplicateSecret k else snapshotSafety rest

-- ── Theorems ────────────────────────────────────────────────────────────────

/-- **(#2300, complete)** No key is BOTH per-pod-secret and shared-config. Over
    the whole finite `CmdKey`, so this is a complete proof of disjointness. -/
theorem partition_disjoint (k : CmdKey) :
    ¬ (k.isPerPodSecret = true ∧ k.isSharedConfig = true) := by
  cases k <;> decide

/-- A shared-config key is never per-pod-secret (a corollary of disjointness,
    stated as a direct implication for reuse). -/
theorem shared_not_per_pod (k : CmdKey) (h : k.isSharedConfig = true) :
    k.isPerPodSecret = false := by
  cases k <;> simp_all [CmdKey.isPerPodSecret, CmdKey.isSharedConfig]

/-- **Soundness AND completeness of the guard.** `snapshotSafety` returns
    `SafeToClone` exactly when the cmdline carries no per-pod-secret key. -/
theorem safe_iff_no_per_pod (keys : List CmdKey) :
    snapshotSafety keys = Safety.safeToClone ↔ ∀ k ∈ keys, k.isPerPodSecret = false := by
  induction keys with
  | nil => simp [snapshotSafety]
  | cons k rest ih =>
      simp only [snapshotSafety, List.mem_cons]
      by_cases hk : k.isPerPodSecret = true
      · rw [if_pos hk]
        constructor
        · intro h; exact Safety.noConfusion h
        · intro hall
          have hc := hall k (Or.inl rfl)
          rw [hk] at hc; exact Bool.noConfusion hc
      · rw [if_neg hk, ih]
        have hkf : k.isPerPodSecret = false := Bool.not_eq_true _ ▸ hk
        constructor
        · intro h k' hk'
          rcases hk' with rfl | hmem
          · exact hkf
          · exact h k' hmem
        · intro hall k' hk'; exact hall k' (Or.inr hk')

/-- **FAIL-CLOSED / ANTI-LAUNDERING.** Once a cmdline is unsafe (carries a per-pod
    key), every SUPERSET (any appended keys) is unsafe too — no additional keys
    launder it back to `SafeToClone`. Dually, `SafeToClone` is downward-closed.
    This is the clone analog of the session-taint ratchet: monotone, no cleansing. -/
theorem unsafe_persists_under_superset (keys extra : List CmdKey)
    (h : snapshotSafety keys ≠ Safety.safeToClone) :
    snapshotSafety (keys ++ extra) ≠ Safety.safeToClone := by
  rw [Ne, safe_iff_no_per_pod] at h
  rw [Ne, safe_iff_no_per_pod]
  intro hall
  exact h (fun k hk => hall k (List.mem_append.mpr (Or.inl hk)))

-- ── Non-vacuity witnesses (mirror the snapshot.rs unit tests) ────────────────

/-- A plain base cmdline (only public/shared keys) is SafeToClone — mirrors
    snapshot.rs `a_plain_base_cmdline_is_safe_to_clone`. Non-vacuous: the list is
    non-empty and its verdict is genuinely `SafeToClone`. -/
example :
    snapshotSafety [.otherPublic, .approvalPubkeys, .net] = Safety.safeToClone := by decide

/-- Every per-pod secret, individually, makes a base unclonable — mirrors
    snapshot.rs `every_per_pod_secret_is_refused`. -/
theorem every_per_pod_secret_refused (k : CmdKey) (h : k.isPerPodSecret = true) :
    snapshotSafety [k] ≠ Safety.safeToClone := by
  simp only [snapshotSafety, h, if_true]; exact fun hc => Safety.noConfusion hc

/-- A cmdline of only shared-config keys is always SafeToClone — the shared keys
    are meant to be baked in. Ties disjointness to the guard. -/
theorem all_shared_is_safe (keys : List CmdKey) (h : ∀ k ∈ keys, k.isSharedConfig = true) :
    snapshotSafety keys = Safety.safeToClone := by
  rw [safe_iff_no_per_pod]
  exact fun k hk => shared_not_per_pod k (h k hk)

-- ── Axiom audit ─────────────────────────────────────────────────────────────

#print axioms partition_disjoint
#print axioms safe_iff_no_per_pod
#print axioms unsafe_persists_under_superset
#print axioms all_shared_is_safe

end SnapshotCloneSafety
