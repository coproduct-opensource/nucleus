/-
  Zero static secrets — what it means for nucleus, as a decidable property.

  A *static secret* is not "a secret that is old". It is a credential whose
  possession is not confined to the one party it speaks for: someone other than
  the claimant can produce a proof the boundary accepts, or a proof once seen can
  be presented again forever. A shared HMAC key is the textbook case: the
  verifier recomputes the MAC, so the verifier can forge it, and so can anyone
  the key was ever delivered to.

  The model is three objects:
    * a `Party` (who can act);
    * a `Credential`: how a boundary checks it (`Check`), who can PRODUCE a proof
      the boundary accepts (`producers`, everyone the signing material reached,
      including through the channel it was delivered on), and whether a presented
      proof expires;
    * a `Boundary`: a verifier, the claimant it authenticates, and the credentials
      it accepts.

  `ZeroStatic sys` holds when no boundary accepts a static credential. It is a
  `Bool`, so the nucleus instance at the end is decided by `decide`, not argued.

  What this file does NOT claim:
    * that the instance is complete — it lists the boundaries traced on
      2026-11-20 (docs/design/zero-static-secrets.md), re-read for the approval
      path after the 2026-11-21 deletion, and a boundary nobody listed is not
      checked. The SDKs' client-side `HmacAuth` is named there as
      untraced;
    * anything about long-lived *asymmetric* keys held by one party (the node's
      approval key, the operator's federation key). Those are not shared secrets;
      whether every key must also rotate is a separate property, not this one;
    * that the Rust matches the instance. Binding it (an extracted boundary table,
      or a census like `node_state_census.rs`) is the next step, not done here.

  Core Lean only: no Mathlib, no `sorry`, no axioms beyond the core three.
-/

namespace StaticSecrets

/-- Who can act. `approver` is whoever provisioned a pod's approval authority. -/
inductive Party where
  | operator
  | cli
  | node
  | toolProxy
  | workload
  | approver
  deriving DecidableEq, Repr

/-- How a boundary checks a presented proof. -/
inductive Check where
  /-- The verifier recomputes the proof with the same key (HMAC). -/
  | sharedKey
  /-- The verifier checks a signature against a public key. -/
  | publicKey
  /-- The kernel attests the peer (vsock, `SO_PEERCRED`); no material is presented. -/
  | kernelChannel
  deriving DecidableEq, Repr

structure Credential where
  name : String
  check : Check
  /-- Everyone who can produce a proof the boundary accepts. -/
  producers : List Party
  /-- A presented proof stops being accepted (a skew window, an expiry, a handshake). -/
  presentedExpires : Bool
  deriving DecidableEq, Repr

structure Boundary where
  name : String
  verifier : Party
  claimant : Party
  accepts : List Credential
  deriving DecidableEq, Repr

/-- What each kind of check implies about who holds the material. A shared key is
    held by whoever checks it; a kernel-attested channel speaks only for its peer. -/
def wellFormedAt (b : Boundary) (c : Credential) : Bool :=
  match c.check with
  | .sharedKey => c.producers.contains b.verifier
  | .kernelChannel => c.producers == [b.claimant]
  | .publicKey => true

def WellFormed (sys : List Boundary) : Bool :=
  sys.all fun b => b.accepts.all (wellFormedAt b)

/-- `c` is a static secret at `b`: a party other than the claimant can produce a
    proof `b` accepts, or a presented proof never expires. -/
def staticAt (b : Boundary) (c : Credential) : Bool :=
  c.producers.any (fun p => p != b.claimant) || !c.presentedExpires

/-- No boundary accepts a static secret. -/
def ZeroStatic (sys : List Boundary) : Bool :=
  sys.all fun b => b.accepts.all fun c => !staticAt b c

/-- Every (boundary, credential) pair that breaks `ZeroStatic`, by name. -/
def violations (sys : List Boundary) : List (String × String) :=
  sys.flatMap fun b => (b.accepts.filter (staticAt b)).map fun c => (b.name, c.name)

/-! ## Theorems -/

/-- Under zero static secrets, only the claimant can produce an accepted proof. -/
theorem zero_static_no_forger (sys : List Boundary) (h : ZeroStatic sys = true)
    (b : Boundary) (hb : b ∈ sys) (c : Credential) (hc : c ∈ b.accepts)
    (p : Party) (hp : p ∈ c.producers) : p = b.claimant := by
  simp only [ZeroStatic, List.all_eq_true] at h
  have hs := h b hb c hc
  simp only [staticAt, Bool.not_or, Bool.not_not, Bool.and_eq_true, Bool.not_eq_true',
    List.any_eq_false] at hs
  have := hs.1 p hp
  simpa using this

/-- Under zero static secrets, every accepted proof expires: a copy is not
    accepted forever. -/
theorem zero_static_proofs_expire (sys : List Boundary) (h : ZeroStatic sys = true)
    (b : Boundary) (hb : b ∈ sys) (c : Credential) (hc : c ∈ b.accepts) :
    c.presentedExpires = true := by
  simp only [ZeroStatic, List.all_eq_true] at h
  have hs := h b hb c hc
  simp only [staticAt, Bool.not_or, Bool.not_not, Bool.and_eq_true] at hs
  exact hs.2

/-- A well-formed shared key is static wherever the verifier is not the claimant:
    the verifier itself can produce the proof. -/
theorem shared_key_is_static (b : Boundary) (c : Credential)
    (hwf : wellFormedAt b c = true) (hk : c.check = .sharedKey)
    (hne : b.verifier ≠ b.claimant) : staticAt b c = true := by
  simp only [wellFormedAt, hk, List.contains_iff_mem] at hwf
  simp only [staticAt, Bool.or_eq_true, List.any_eq_true]
  exact Or.inl ⟨b.verifier, hwf, by simpa using hne⟩

/-- So zero static secrets rules out shared keys between distinct parties. -/
theorem zero_static_no_shared_key (sys : List Boundary)
    (hwf : WellFormed sys = true) (h : ZeroStatic sys = true)
    (b : Boundary) (hb : b ∈ sys) (hne : b.verifier ≠ b.claimant)
    (c : Credential) (hc : c ∈ b.accepts) : c.check ≠ .sharedKey := by
  intro hk
  simp only [WellFormed, List.all_eq_true] at hwf
  have hs := shared_key_is_static b c (hwf b hb c hc) hk hne
  simp only [ZeroStatic, List.all_eq_true] at h
  have := h b hb c hc
  simp [hs] at this

/-- Retiring credentials never breaks the property: deleting is safe. -/
theorem retire_preserves (sys : List Boundary) (keep : Boundary → Credential → Bool)
    (h : ZeroStatic sys = true) :
    ZeroStatic (sys.map fun b => { b with accepts := b.accepts.filter (keep b) }) = true := by
  simp only [ZeroStatic, List.all_eq_true, List.mem_map] at h ⊢
  rintro _ ⟨b, hb, rfl⟩ c hc
  simp only [List.mem_filter] at hc
  exact h b hb c hc.1

/-- The property is exactly "no violations". -/
theorem zero_static_iff_no_violations (sys : List Boundary) :
    ZeroStatic sys = true ↔ violations sys = [] := by
  simp only [ZeroStatic, violations, List.all_eq_true, List.flatMap_eq_nil_iff,
    List.map_eq_nil_iff, List.filter_eq_nil_iff, Bool.not_eq_true']
  constructor
  · intro h b hb c hc
    simpa using h b hb c hc
  · intro h b hb c hc
    simpa using h b hb c hc

/-! ## Nucleus, traced 2026-11-20 on `main` (5fab70962)

  Each entry names where it was read. Producers are who can make an accepted
  proof, including parties the material reached in transit. Two instances
  follow: `nucleusBefore20261121`, the trace as read, and `nucleusMain`, the
  same boundaries after the approval HMAC was deleted.
-/

/-- The node's API: mTLS with the provisioned client identity alone (#3297). -/
def nodeApi : Boundary :=
  { name := "node API", verifier := .node, claimant := .cli,
    accepts := [{ name := "CLI client certificate", check := .publicKey,
                  producers := [.cli], presentedExpires := true }] }

/-- The pod's identity to the node: the SVID the guest fetched over vsock
    (`guest-init` `fetch_identity`; `sandbox_proof.rs` tiers 1-2). -/
def podIdentity : Boundary :=
  { name := "pod identity", verifier := .node, claimant := .toolProxy,
    accepts := [{ name := "SVID", check := .publicKey,
                  producers := [.toolProxy], presentedExpires := true }] }

/-- The node reaching a pod's tool-proxy: vsock, which authenticates the node
    (`retired_config.rs`: "every pod is reached over a transport that
    authenticates the node"). -/
def nodeToProxy : Boundary :=
  { name := "node to tool-proxy", verifier := .toolProxy, claimant := .node,
    accepts := [{ name := "vsock peer", check := .kernelChannel,
                  producers := [.node], presentedExpires := true }] }

/-- The workload reaching its tool-proxy: the door socket, authenticated by the
    workload's uid as the kernel reports it (#3031 option B). -/
def workloadDoor : Boundary :=
  { name := "workload door", verifier := .toolProxy, claimant := .workload,
    accepts := [{ name := "peer uid", check := .kernelChannel,
                  producers := [.workload], presentedExpires := true }] }

/-- The Ed25519 approval signature: the node delivers only the PUBLIC half as
    `nucleus.approval_pubkeys` (`firecracker_config.rs`); drand-anchored skew. -/
def approvalSignature : Credential :=
  { name := "Ed25519 approval signature", check := .publicKey,
    producers := [.approver], presentedExpires := true }

/-- The legacy approval HMAC, deleted 2026-11-21 and kept here for
    `nucleusBefore20261121`: `NUCLEUS_TOOL_PROXY_APPROVAL_SECRET`, from
    `nucleus.approval_secret` on the kernel command line or
    `/etc/nucleus/approval.secret`. The tool-proxy recomputes it, and the
    command line is world-readable inside the guest, so the workload holds it
    too (`guest-init` `proxy_auth_env`). -/
def approvalHmac : Credential :=
  { name := "legacy approval HMAC", check := .sharedKey,
    producers := [.approver, .toolProxy, .workload], presentedExpires := true }

def approvals (accepts : List Credential) : Boundary :=
  { name := "tool-proxy approvals", verifier := .toolProxy, claimant := .approver,
    accepts }

/-- The operator's federation assertion, signed by a key only the operator holds
    (`operator_key.rs`), minted moments before the exchange that spends it. -/
def operatorFederation : Boundary :=
  { name := "operator federation", verifier := .node, claimant := .operator,
    accepts := [{ name := "operator assertion", check := .publicKey,
                  producers := [.operator], presentedExpires := true }] }
/-! ### Before the deletion: `main` at 5fab70962, 2026-11-20

  Kept under a dated name so the violation the deletion removed stays on the
  record, decided rather than remembered. -/

def nucleusBefore20261121 : List Boundary :=
  [nodeApi, podIdentity, nodeToProxy, workloadDoor,
   approvals [approvalSignature, approvalHmac], operatorFederation]

example : WellFormed nucleusBefore20261121 = true := by decide

/-- Before 2026-11-21 nucleus was not zero-static, and the approval HMAC was
    the only reason. -/
theorem before_violations :
    violations nucleusBefore20261121 =
      [("tool-proxy approvals", "legacy approval HMAC")] := by
  decide

theorem before_not_zero_static : ZeroStatic nucleusBefore20261121 = false := by decide

/-- And the workload, in particular, could forge an approval then: the property
    the deletion removed, stated for the party it mattered for. -/
theorem workload_forged_approvals_before_20261121 :
    Party.workload ∈ approvalHmac.producers ∧
      approvalHmac ∈ (approvals [approvalSignature, approvalHmac]).accepts := by
  decide

/-! ### After the deletion: this branch, 2026-11-21

  The tool-proxy's `/v1/approve` accepts only the Ed25519 approval signature
  (`auth::select_auth_tier` has one approval tier; `ApprovalKeys` wraps the
  Ed25519 verifier alone), refuses `--approval-secret` /
  `NUCLEUS_TOOL_PROXY_APPROVAL_SECRET` by name at startup
  (`retired::refuse_approval_secret`), and `guest-init` no longer exports
  `nucleus.approval_secret` or `/etc/nucleus/approval.secret`. The other
  boundaries are unchanged from the 2026-11-20 trace. -/

def nucleusMain : List Boundary :=
  [nodeApi, podIdentity, nodeToProxy, workloadDoor,
   approvals [approvalSignature], operatorFederation]

example : WellFormed nucleusMain = true := by decide

/-- The traced boundaries are zero-static: no violations. -/
theorem main_violations : violations nucleusMain = [] := by decide

theorem main_zero_static : ZeroStatic nucleusMain = true := by decide

/-- `main` is exactly the 2026-11-20 instance with the approval HMAC retired
    and nothing else changed, so `retire_preserves` is the shape of the step. -/
theorem main_is_before_with_hmac_retired :
    nucleusMain =
      nucleusBefore20261121.map fun b =>
        { b with accepts := b.accepts.filter fun c => c != approvalHmac } := by
  decide

/-- No approval on `main` can be produced by the workload, or by the
    tool-proxy that checks it: only the approver. -/
theorem only_the_approver_approves_on_main :
    ∀ c ∈ (approvals [approvalSignature]).accepts, c.producers = [.approver] := by
  decide

end StaticSecrets
