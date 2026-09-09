# Nucleus authorization model — static read (2026-09-08)

Scope: `crates/portcullis*`, `ck-*`, `nucleus-policy*`, `nucleus-permission-market`, `nucleus-econ-*`, `nucleus-ifc*`, `docs/permissions.md`, `docs/constitutional-kernel/spec-v0.1.md`, `docs/theory/`, `PolicyManifest.toml`, plus the enforcement points in `nucleus-tool-proxy` and `nucleus-node` that consume them. No builds run; all claims are from source.

## 0. One-paragraph shape

There are **four separate authorization systems** in the tree, with different data models and different degrees of wiring:

| Layer | Data model | Decision fn | Authority source | Runtime carrier | Status |
|---|---|---|---|---|---|
| **A. Portcullis lattice** (`crates/portcullis`) | `PermissionLattice` = 13 ops × {Never,LowRisk,Always} + obligations + paths + budget + commands + time + min-isolation | `Kernel::decide` (`kernel.rs:1125`) | node root Ed25519 key via `LatticeCertificate` | signed cert chain / `AttenuationToken`; in-proc `Kernel` session | **live** in tool-proxy & node |
| **B. Constitutional kernel** (`ck-types/ck-policy/ck-kernel`) | `PolicyManifest` (5 string-set axes + budget + proof-reqs + amendment rules) | `check_monotonicity` + `Kernel::admit` | witness Ed25519 sigs; human co-signatures for constitutional class | TOML file in repo, CI gate | **live in CI only**, Preflight mode (signatures skipped) |
| **C. PARC policy kernel** (`nucleus-policy-kernel/-cert/-pca`) | `Policy{rules: Vec<Rule{Permit/Forbid, principal, action, resource: Any|Exact}>}` | `decide` (default-deny, forbid-overrides), `governance_monotone` | issuer Ed25519 on recompute certs | self-standing `Certificate` | **library + verifier only**; no runtime PEP consults it |
| **D. IFC labels** (`nucleus-ifc-kernel`, `nucleus-ifc`) | `IFCLabel` (conf, integ, authority, provenance, freshness, derivation) over a causal flow DAG | `discharge::preflight_action` (8 obligations), `FlowDeclaration::decide` | none (derived from observed sources) | in-proc `FlowGraph`; `DischargedBundle` sealed type | **live** in tool-proxy read/write paths |

`nucleus-policy` (`crates/nucleus-policy/`) is a **Cargo.toml with no `src/`** — an empty stub described as "Policy DSL for zero-permission-prompt AI agent authorization".

---

## 1. Layer A — Portcullis permission lattice (the live runtime model)

### Data model
- `PermissionLattice` (`crates/portcullis/src/lattice.rs:60-118`): `capabilities: CapabilityLattice`, `obligations: Obligations`, `paths: PathLattice`, `budget: BudgetLattice`, `commands: CommandLattice`, `time: TimeLattice`, `uninhabitable_constraint: bool` (pub(crate)), `minimum_isolation: Option<IsolationLattice>`, plus `id/derived_from/created_by` audit metadata.
- `CapabilityLattice` (`crates/nucleus-ifc-kernel/src/capability_lattice.rs:21-35`): 13 fixed fields `read_files, write_files, edit_files, run_bash, glob_search, grep_search, web_search, web_fetch, git_commit, git_push, create_pr, manage_pods, spawn_agent`, each a `CapabilityLevel` 3-chain (`capability_level.rs:21`), plus an `extensions: BTreeMap<String, CapabilityLevel>` for string-keyed tools (`portcullis/src/capability.rs:33`, `tool_surface.rs:1-20` — absent key meets to `Never`, so children can drop but never add tools).
- `Operation` enum (`nucleus-ifc-kernel/src/ifc_ops.rs:23-37`) is frozen at 13 discriminants for Aeneas extraction; `SinkClass` (`ifc_ops.rs:220-243`) has 19 sink classes (HTTPEgress, EmailSend, CloudMutation, SecretRead, …) that are richer than the 13 ops but only reachable via `hook_adapter::classify_sink` and `PolicyRuleSet`.
- `PathLattice` (`path.rs:86-93`): `allowed`/`blocked` glob sets + `work_dir`. `CommandLattice` (`command.rs:35-51`): allow/block program sets, `CommandPattern` rules, `allow_metacharacters`. `BudgetLattice` (`budget.rs:23-30`): `max_cost_usd: Decimal`, `consumed_usd`, token caps. `TimeLattice` (`time.rs:14-18`): `valid_from/valid_until`.
- Obligations (`capability.rs:51`) are a `BTreeSet<Operation>` requiring approval; the **uninhabitable-state nucleus** (`capability.rs:257-330`) auto-inserts `GitPush/CreatePr/RunBash` obligations whenever private-read ∧ untrusted-web ∧ exfil are all ≥ LowRisk. `Deserialize` forces `uninhabitable_constraint = true` and normalizes (`lattice.rs:190-222`) so a JSON payload cannot disable it.

### Decision procedure
`Kernel::decide(op, subject: &str)` (`kernel.rs:1125-1440`) runs in order: min-isolation → time → budget → capability level (`Never` ⇒ deny) → airgap gate → egress host policy (`egress_policy.rs`, `.nucleus/egress.toml`) → `PolicyRuleSet` (source/artifact/sink rules, fail-closed, `portcullis-core/src/policy_rules.rs:1-12`) → enterprise sink allowlist → path glob → command pattern → certificate `SinkScope` (paths/hosts/git refs, `certificate.rs:454-462`) → IFC flow-label taint → static obligation/approval → dynamic exposure gate. `Allow` yields a linear, sealed `DecisionToken` (`kernel.rs:383-392`; Kani `proof_decision_token_unforgeable`). Session is monotone: `Kernel::attenuate` only meets (`kernel.rs:1698-1716`); exposure only grows.

Optional layers exist in-crate but are **not wired in tool-proxy**: Cedar bridge (`cedar_bridge.rs`, `set_cedar_policy` at `kernel.rs:1669`, feature `cedar`) and CEL `constraint::Policy` nuclei (`constraint/mod.rs`) — `grep` finds no caller outside portcullis. DLC-D says-credential admission (`kernel/dlc.rs`) IS wired (`tool-proxy/main.rs:1878`) when `NUCLEUS_DLC_*` env is present.

### What can / cannot be expressed
- Can: per-op 3-level ceilings, path/host/ref scoping, command allow/deny, USD + token budget, validity window, minimum isolation, approval obligations per op, custom extension tools at 3 levels.
- Cannot: parameter-level constraints beyond `subject` string (no "push only to branch X unless …" except via `SinkScope.allowed_git_refs`); no rate limits/counts per op (only aggregate budget); no time-of-day/recurrence; no conditions over request context except through the unwired CEL/Cedar layers; no "n-of-m approvers"; no per-principal differentiation inside one lattice (the lattice is the principal's authority, identity lives outside in `IdentityPolicySet`, `identity.rs:153`).

### Authority & carriage
- Root authority is the **node's persistent Ed25519 root key** (`nucleus-node/src/pod_authority.rs:1-50`). Every pod gets a `LatticeCertificate` (`certificate.rs:115-180`): Biscuit-style `AuthorityBlock` + `DelegationBlock`s, each block signed by the previous hop's ephemeral `next_key`, SHA-256 hash-chained, with proof-of-possession `final_signature`. `verify_certificate` (`certificate.rs:1344-1430`) re-executes `leq()` per hop (monotone attenuation), checks `SinkScope` containment, expiry per block, depth ≤ 10.
- Carried on the wire as `AttenuationToken` base64 (`token.rs:101-290`, delivered as `NUCLEUS_POD_CERT` + pinned `NUCLEUS_CERT_ROOT_PUBKEY`; `tool-proxy/src/pod_cert.rs:1-40`). The guest holds only the public chain; tool-proxy verifies once against the pinned anchor and builds `Kernel::from_certificate` (`main.rs:1873`). The on-disk `PolicySpec::{Profile{name}, Inline{lattice}}` (`nucleus-spec/src/lib.rs:155-160`) is overridden by the cert (`main.rs:1521-1541`).
- Cross-host delegation: external mTLS callers may present `x-nucleus-delegation-cert`; node verifies, requires leaf == authenticated SPIFFE id, then **re-roots** with caller fingerprint as `provenance` (RFC 8693 `act` semantics) — `pod_authority.rs:30-45`. Only the `SpiffeMtls` tier binds identity; any other tier presenting a cert is refused (`pod_cert.rs:26-40`).
- **Budget conservation** is not in the credential: `PermissionLattice::delegate_to` (`lattice.rs:516-547`) only checks `requested ≤ remaining` and never decrements, so N children could get N× budget; the fix is a per-parent `BudgetLedger` (`budget_ledger.rs:1-60`) held only by the node (`pod_authority.rs`, the sole user). Invariant `Σ live child allocations + consumed ≤ max`.
- Delegation forensic chain: `delegation.rs:122` reconstructs from audit events; `MeetJustification` (`delegation.rs:257`) records per-dimension `RestrictionReason` (CeilingExceeded, UninhabitableStateDemotion, BudgetExceeded, …) inside each `DelegationBlock`.

### Profiles / policy language
- Built-in presets are Rust constructors (`lattice.rs:619-1256`: read_only, web_research, code_review, fix_issue, pr_review, codegen, pr_approve, orchestrator…), mirrored in `docs/permissions.md` and `sdk/python/nucleus_sdk/profiles.py` (which still says "12 operations" — drift vs 13).
- Declarative `ProfileSpec` YAML/TOML (`profile.rs:50-260`): capabilities, obligations, paths, budget, time, optional CEL constraints; `ProfileRegistry::canonical()` embeds them. `portcullis-profiles` (`crates/portcullis-profiles/src/lib.rs`) is a 240-line `TaskKind` preset table (CodeReview/BugFix/DocsEdit/Research → allowed/approval-required op lists).
- `TrustProfile` (`trust.rs:43`) pairs a cap ceiling with an isolation floor; `AutonomyCeiling` (`portcullis-core/src/autonomy.rs:37`) is an org-level cap **with zero callers outside its own file**. `EnterpriseAllowlist` (`enterprise.rs:83`) and `ManagedSettings` (`managed_settings.rs:98`) are self-described "schema only"/"distribution infrastructure is separate work", though `Kernel::set_enterprise` does exist (`kernel.rs:1809`).
- `portcullis-core/src/delegation.rs:1-20` states plainly that `DelegationConstraints` is "a proof subject and a test oracle, not a runtime authority" (the `Kernel::set_delegation` gate was removed).

### Approvals (the weakest live link)
- Static obligations produce `Verdict::RequiresApproval`. In-process, `Kernel::grant_approval` / `issue_approved_token` (`kernel.rs:1747`, `1905`) are **unauthenticated** — anyone with `&mut Kernel` can approve; they are merely audited (Kani `proof_issue_approved_token_is_audited`).
- Tool-proxy `/v1/approve` (`main.rs:2110`) requires either an HMAC secret or, preferably, Ed25519 approver **public keys** + drand-anchored nonce (`main.rs:150-158, 386-392, 1612-1640`) — a real out-of-band principal. But the code itself documents **#2406**: `http_kernel_decide` returns `RequiresApproval` before the sandbox path that consults `ApprovalRegistry`, so "an operator who grants an approval here gets a 200 and no effect" (`mediation.rs:161-190`, `main.rs:3105-3125`). Approval is therefore only effective on the sandbox-level `ApprovalRequired` retry path (`main.rs:2925-2940`).
- `/v1/escalate` (`escalate.rs:150-230`) validates an `EscalationRequest` against `EscalationPolicySet` (requestor/approver SPIFFE patterns, TTL, distinct-chain, attestation; `escalation.rs:609-760`), mints an `EscalationGrant` with drand round — and **never touches the kernel** (no `kernel` reference in `escalate.rs`); the grant is logged and returned, not applied. Runtime widening is thus documented but non-functional.
- Multi-principal: only the SPIFFE `approver_pattern` and a pubkey *list* (any one key suffices). No threshold/m-of-n at runtime; threshold signatures exist only in ck-kernel constitutional path (§2).

### Revocation & time
- Certificates have per-block `not_after` and no revocation list; `grep revok` finds nothing in `certificate.rs`/`token.rs`. `TimeLattice` is the only expiry primitive; `TimeLattice::extend` (`time.rs:130`) exists and is not lattice-monotone.
- The revocation substitute is **fleet lockdown**: node `WatchLockdown` gRPC broadcast (`nucleus-node/src/main.rs:3688-3740`, scope = all/pod/label) flips an `AtomicBool` in each tool-proxy over mTLS (`lockdown_client.rs:1-15`), and the lattice has a lockdown-to-`Never` path (`lattice.rs:683`). This is coarse (read-only for a pod), push-based, and fail-safe only if the stream is up.

---

## 2. Layer B — Constitutional kernel (monotone self-amendment)

- Model (`crates/ck-types/src/manifest.rs:18-25`): `PolicyManifest{capabilities: CapabilitySet(5 BTreeSet<String> + max_parallel_tasks), io_surface: IoSurface(5 sets), budget_bounds(8 u64), proof_requirements(3 sets), amendment_rules}`. Order = per-axis subset (`manifest.rs:74-82`, `155`, `236`, `267`). `AmendmentRules::weakened_flags_over` (`manifest.rs:338-380`) is the anti-coup check: monotone flags cannot be disabled and `constitutional_human_signatures` cannot be lowered — checked unconditionally.
- Decision: `ck_policy::check_monotonicity` (`crates/ck-policy/src/lib.rs:37-110`, pure) then `ck_kernel::Kernel::admit_with_files` (`crates/ck-kernel/src/lib.rs:173-330`): parent must be latest admitted (dual-DAG), `PatchClass::Constitutional` cannot self-merge, witness structurally complete, signatures (`SignaturePolicy::Enforced` vs `SkipForTesting`), digest continuity, `policy_before` must equal stored parent policy, then monotonicity, then lineage append (`lineage.rs:18`, in-memory `LineageStore`, restorable). `admit_constitutional` (`lib.rs:442-580`) requires ≥ N strict-Ed25519 `HumanSignature`s.
- Authority: witness `BundleSignature`s verified by `SignatureVerifier` with optional required roles (`ck-types/src/witness.rs:119-255`); humans sign the witness `signing_payload()`.
- Carriage/wiring: `PolicyManifest.toml` at repo root (caps: `/workspace`, `crates.io`/`github.com`, 6 tools, $5, 200k tokens; `constitutional_human_signatures = 1`). Enforced by `cargo xtask policy-gate` via `gate_manifest_amendment(..., GateMode::Preflight)` (`crates/xtask/src/main.rs:243`; `ck-kernel/src/gate.rs:20-40`) — **Preflight synthesizes a passing witness and skips signatures**; `GateMode::Admit` (fail-closed, real keys) is defined but unused in-repo ("used once trust-root key material exists"). Nothing at pod runtime reads `PolicyManifest.toml`; the manifest governs the repo, not the agent session, and its `tools_allow` vocabulary (`Read`, `Edit`, `Bash`…) does not map to portcullis `Operation`s.
- Proofs: 17 Kani harnesses (`ck-kernel/src/kani.rs`), Lean `Ck.Policy` (16 theorems) + `Ck.PolicyMulti` (11) — the latter exists precisely because the single-carrier Lean model was more permissive than the per-axis Rust (`ck-policy/lean/Ck/PolicyMulti.lean:1-30`), an honest, documented gap fix. Aeneas-extracted mirror at `ck-policy/src/extracted.rs`.

## 3. Layer C — PARC kernel + recompute certificates (Proof-Carrying Authorization)

- `nucleus-policy-kernel/src/lib.rs:42-125`: `Rule{effect: Permit|Forbid, principal/action/resource: Any|Exact(String)}`; `decide` = default-deny, forbid-overrides; `governance_monotone(old,new)` decides `allowed(new) ⊆ allowed(old)` **exactly** by enumerating representative requests over the finite Exact-alphabet (`lib.rs:180-209`). Expressiveness is deliberately tiny: no globs, no attributes, no conditions, no obligations.
- `nucleus-policy-cert/src/lib.rs`: Ed25519 `Certificate` binding policy commitment + `AuthoritySubject::{Decision, Governance}` + witness, verified by recompute (`verify`, `lib.rs:805`); `ResidualTrust` recorded. `nucleus-pca/src/lib.rs` unifies four verifiers (`PolicyCert`, `Delegation` = `portcullis::verify_certificate`, `Flow`, `Isolation`).
- Consumers: only `nucleus-pca`; `nucleus-cred-broker` lists it as a **banned** dependency (`cred-broker/src/lib.rs:332-338`). No PEP evaluates PARC rules against live tool calls. Status: implemented library + verifier, **not enforced anywhere at runtime**.

## 4. Layer D — IFC as authorization

- `nucleus-ifc-kernel` is the dependency-free Aeneas target (`lib.rs:1-30`): `CapabilityLattice`/`CapabilityLevel`, label lattice, `decide_pure`, `discharge` pipeline. `DischargedBundle` (`discharge.rs:1-40`) is sealed and required by `portcullis_effects::authority::Authority::new` at effect sites (`tool-proxy/main.rs:2900-2912`), checking 8 obligations incl. `WithinDelegationCeiling` and `InScopeWithTask` (task token `TokenScope{allowed_operations, allowed_paths}`, `nucleus-provenance-memory/src/taskref_token.rs:76-80` — a second Biscuit-style attenuating chain distinct from the cert).
- Declassification is the only "authority increase" primitive: signed `DeclassificationToken`s (`portcullis/src/token_sign.rs`) verified against governor keys provisioned from node env only (`main.rs:1885-1900`), fail-closed when empty.
- `nucleus-ifc::FlowDeclaration::decide` (`decision.rs`) is a model-level declared-input check with `ConformanceCertificate`, proptest-tied to the kernel.

## 5. Economics

- `BudgetLattice` (USD Decimal + tokens) is the only budget the kernel enforces (`kernel.rs:1175`, `charge` at `1719`). Node-side `BudgetLedger` conserves across spawn.
- `nucleus-permission-market` (`src/lib.rs:1-60`, `market.rs:121`): Lagrangian λ-pricing over 4 dimensions (Filesystem, CommandExec, NetworkEgress, Approval) with `TrustTier` discounts; bids arrive via `x-nucleus-permission-bid` (`tool-proxy/main.rs:2380`) and are Galois-bridged to the lattice (`tool-proxy/src/cert_bridge.rs:1-25`, α: 13 dims → 4). Bids are **unsigned** and, per `pod_cert.rs`, historically were a downgrade path; now cert failures error rather than fall through.
- `nucleus-econ-kernels` (integer VCG, Pigou, settlement, commons; Lean-parity tests) and `nucleus-econ-types` (`MicroUsd`, ids) are settlement/auction math consumed by recompute/creditworthiness/witness crates — **not** part of the authorization decision.

## 6. Verification footprint (authz-relevant)

- Kani: 130 harnesses in `portcullis/src/kani.rs` (meet laws, delegation ceiling, nucleus idempotence, token unforgeability, exposure monotonicity, isolation), 6 certificate harnesses (`kani/certificate_harnesses.rs`), 6 in `portcullis-core/src/delegation.rs`, 34 in `ck-kernel`. Lean: ~105 files in `portcullis-core/lean` incl. `CertChainMonotoneExtracted`, `AttenuationChainExtracted`, `SessionCeilingProofs`, `DelegationProofs`, `CapabilityResiduatedQuantaleProofs`, `MediationScopeExtracted`; `docs/PROOFS.md` is the honesty matrix. Note: proofs cover the lattice algebra and chain verification, **not** the approval/escalation plumbing, lockdown, or the node ledger.

## 7. Implemented vs stubbed vs documented-only (skeptical summary)

Implemented & live: PermissionLattice + Kernel mediation; LatticeCertificate mint/delegate/verify; node `PodAuthority` (root-of-trust, re-rooting, BudgetLedger); pinned-anchor cert boot; lockdown broadcast; egress.toml; PolicyRuleSet; DLC admission; signed declassification; IFC discharge; ck monotonicity gate in CI (Preflight).
Implemented but unwired / no callers: Cedar bridge, CEL constraint policies, `AutonomyCeiling`, `DelegationConstraints` (explicitly proof-only), `EnterpriseAllowlist`/`ManagedSettings` (schema-only), PARC kernel/cert/PCA (no PEP), `GateMode::Admit`, `TaskKind` profiles.
Documented but broken/absent: HTTP-path approval satisfaction (#2406, admitted in code); `/v1/escalate` grants never applied to a kernel; certificate revocation (none; expiry + lockdown only); runtime enforcement of `PolicyManifest.toml`; `nucleus-policy` crate (empty).

## 8. Read against the North Star

(1) Model-agnostic: yes — authority is bound to SPIFFE ids and Ed25519 keys, never a model. (2) Breadth of effects: the *authorization vocabulary* is 13 core ops (+ string extensions) with only `subject: &str` as parameter; 19 `SinkClass`es exist but are reachable only via rule sets. Real-world effects beyond files/git/web/shell (email, cloud, tickets) have sink classes but no op-level capability. (3) Expressiveness: strong on attenuation, scoping, time bounds, budgets (with node-side conservation), provenance; weak on approvals (single-key, partly dead path), escalation (non-functional), revocation (fleet-level only), multi-principal (constitutional CI path only). (4) Structural incapability: the lattice/cert chain is the best-proven part (Kani + Lean, sealed tokens, pinned anchor, no signing key in guest); the trust boundary that is not proven is the tool-proxy's approval/escalation glue and the `SkipForTesting`/Preflight defaults. (5) Ratchets: ck-kernel is a genuine monotone ratchet over repo policy; no measurement exists of the *delegatable envelope* growing (the lattice vocabulary is frozen at 13 for proof reasons, which is the opposite of "continuously expand").
