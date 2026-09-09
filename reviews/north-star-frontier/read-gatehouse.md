# gatehouse, read end to end — and what it means for nucleus's North Star

Static read of `/home/user/gatehouse` (53 commits, ~31k Rust LOC across 19 crates + 3 spikes, ~400 test fns, ~6k hand-written Lean + 8k Aeneas-generated). No builds run. "Implemented / stubbed / doc-only" is marked where it matters.

## 1. What gatehouse is

`README.md` (10 lines): a **gate** declares inputs, environment, effect capabilities, command, outputs; a **pipeline** is a DAG of gates in **writ**, a small dependently typed language whose well-typed plans carry proofs; each execution mints a signed, content-addressed **receipt** in a witnessed transparency log; the merge queue verifies receipts instead of re-running.

The assurance ledger (`docs/assurance/gatehouse-assurance.md:11-17`) states one sentence and earns it row by row (A-1..A-20, lines 32-51) with a four-value vocabulary PROVED / DECIDED / TESTED / NOT-YET (lines 21-26). Population pins: `assurance/ratchet.txt` `CLAUSES=20 NOT_YET=5`. Enforced by `crates/xtask/src/ledger.rs` (a port of nucleus's `check-ci-assurance-ledger.sh`, line 3), `gates.rs` (port of `check-gates-can-fail.sh`, `UNCOVERED_CEILING = 0` at line 21), and `trusted_base.rs`.

## 2. How gates declare capabilities and how a plan is bounded by a ceiling

**The lattice, in writ** — `prelude/ci.writ:51-53`:
`Cap = Σ(net: Enum 3)(exec: Enum 3)(wallMs)(cpuMs)(memMb)(fsRead: List Bytes)(fsWrite: List Bytes)(secrets: List Bytes)` with `net: None<Pinned<Full`, `exec: NoExec<Scoped<Any` (line 48). Order `leqCap` (65-73): rank on enums, ≤ on numbers, `subsetGlob` on pattern sets, `subsetBytes` on secret names. `subsetGlob` (44-45) is *semantic* containment via the kernel primitive `globSubsumes` (`crates/writ-kernel/src/lib.rs:716 prim_glob_subsumes`, sound and deliberately incomplete — `trusted-base.txt:46-55`). Commit `7a6a44a` records that before this the lattice "was an ordering on how patterns are SPELLED".

**Gate / Pipeline / Policy** — `ci.writ:83-85` `Gate = (name, hash, scope, env, cap, cmd, timeoutMs, outputs)`; `Policy = (ceiling: Cap, required: List Bytes, queueBudgetMs, maxGates)` (116). **Admissibility** (151-152) = `acyclic_b` (125) ∧ `hermetic_b` (130: net None, no secrets, `fsRead ⊆ scope`, timeout ≤ wallMs) ∧ `bounded_b` (138: every gate's cap `leqCap` the ceiling) ∧ `covered_b` (142) ∧ `budget_b` (148: sum of timeouts ≤ budget; "v1: no path analysis").

**The proof is by evaluation, the checker is verified.** `.gatehouse/pipeline.writ:20`: `let admissible : So (ci.admissible_b pipeline policy) = oh`. `gate plan check` (`crates/gate/src/lib.rs:56 plan_check`) elaborates (untrusted, `crates/writ`) into a flat certificate — arena, typing rows, reduction rows, substitution/shift rows — and `writ-kernel` re-checks each row locally against lower rows only (`crates/writ-kernel/src/lib.rs:1-19`; no Vec/generics/closures, Aeneas subset). Soundness: `lean-kernel/WritKernelTy.lean:1898 theorem check_sound : check c = ok ⇒ HasType c 0 root root_ty`, against `WritKernelSpec.lean:524 inductive HasType`, over the *extracted* kernel (`lean-kernel/generated/WritKernel/Funs.lean`, drift-checked by `xtask assure extraction-drift`). Axiom closure `{propext, Classical.choice, Quot.sound}` + one disclosed axiom, `prim_ed25519_verify` (`lean-kernel/.axiom-audit-exceptions`). Golden differential: 17+ certificates decided by both the Rust and the extracted Lean kernel (`scripts/check-kernel-golden.sh`, `lean-kernel/Golden.lean` — `check_core` only, since Ed25519 is noncomputable there). Ledger row A-12 PROVED, A-13 DECIDED. The ledger is explicit that this is *soundness of the decision procedure*, not completeness, subject reduction, normalization or consistency (lines 60-61).

Eleven opaque primitives (sha256, bytes cat/eq/slice, decimal, be64, path order, glob match/subsume, sha1, ed25519) enter as one axiom each at the extraction boundary; ten are implemented twice (Rust and Lean) and forced to agree by golden fixtures (`trusted-base.txt:25-110`). The population is *enumerated* from `crates/xtask/src/drift.rs#PRIMITIVES`, so an unlisted primitive is red, not an oversight (A-20).

Certificate cost is ratcheted: `fixtures/plans/cost-ceilings.txt` pins `NODES/RED/SUB` row counts for a 100-gate plan; `docs/writ/costs.md` (S1-S9) records each design choice with measurements (e.g. certified glob matching at ~9.9M rows/240 MB forced the matcher into a primitive; a receipt acceptance certificate is 572 KB of a 2 MB budget).

**Skeptical notes.** (a) The lattice exists twice: `gatehouse_types::Cap::leq` (`crates/gatehouse-types/src/lib.rs:85`) in Rust and `leqCap` in writ; only the writ side is kernel-checked, the Rust side is what the runner/agent consult. (b) `xtask assure plan-binding` (`crates/xtask/src/plan_binding.rs`) ties `pipeline.writ` to `.gatehouse/gates/*.json`, but `MISSING_FILE_CEILING = 4`: of 5 dogfood gates only `fmt.json` exists. (c) Nobody signs the ceiling: `pipeline.writ` is a file in the tree under test, and `PUT /v1/{tenant}/plan` (`crates/gatehouse-controld/src/lib.rs:144`) is guarded by one shared bearer token. There is no monotonicity check on ceiling changes and no principal identity behind them — see §6.

## 3. What a receipt binds

Envelope (`crates/gatehouse-types/src/lib.rs:457-565`): vendored `nucleus-receipt` shape — `Receipt{version, session{session_id, issuer_kid, issued_at, parent_chain}, projections[], root_hash_hex (BLAKE3), signature_b64 (Ed25519 verify_strict)}`, JCS-canonical signing bytes (509). The `ci` projection `CiVerdict` (313-336) binds: `repo, plan, gate_name, gate_def, scope, env, tree, commit, tree_kind, verdict, exit_code, started/finished, log_blake3, outputs[], sandbox{substrate, runner_digest, image, net_probe, caps_enforced}, signer_chain[SignerLink{kid, kind, tier}], certificate?, binding{nonce, valid_until_index, bound_context}?`. Lookup key is `(gate_def, scope)` (340); `gate_def` is the content hash of the gate's normal form (`crates/writ/src/hash.rs:150 gate_hash`, A-11); `scope` is the hash of the tree restricted to the gate's scope (`crates/gatehouse-scope`, proved in `lean/Scope.lean`).

Verification (`crates/gatehouse-verify/src/lib.rs:186-278`), three-valued (`Outcome::{Verified, Refuted, CouldNotLook}`, 79): trust-first blockers → `authenticate` (148: version, known kid, root+signature over canonical tuple, exactly one ci projection, chain head = issuer) → `NetProbeReached ∧ held ⇒ refuse` → `effective_tier` (115: min of key tier, every chain link, substrate cap, tree kind) vs `class.tier_floor()` (Required ⇒ NodeAttested) → bindings `gate_def/scope/env/tree/plan` against an `Expectation` → freshness binding → inclusion proof and signer window at that index. The Expectation is projected from the stored plan, never from the caller (`crates/gatehouse-control/src/lib.rs:193 expectation_for`, A-4). Same decision runs natively, in wasm, and via `gatehouse-decide` for a byte-for-byte differential (`decide_json`, 297). `gatehouse-certify` additionally re-expresses acceptance as a writ certificate (`prelude/verify.writ:404 accepts`, 15 conjuncts) so acceptance can be kernel-checked; positive direction only, by design.

**Identity behind the signature.** `gatehouse-ca`: developer credentials (8 h, tier Developer) and job credentials (2 h, tier NodeAttested) bound to `JobBinding{job_id, gate_def, env, tree, substrate, agent}` (`crates/gatehouse-ca/src/lib.rs:160-170`), issued by a node CA held only by controld (`controld/src/lib.rs:410-470`); the runner generates an in-memory key per run, the gate command never sees it (`docs/executor.md:27,122-124`). SPIFFE-shaped names (`spiffe://gatehouse/job/…`) but no SVIDs; `SignerLink.kind = "attested_svid"` is a string nothing produces. `LaunchAttested`/`HardwareAttested` tiers exist in the enum only.

## 4. Log and witness

`gatehouse-tlog`: RFC 6962 tree over receipt leaves (`types/lib.rs:391-447`), C2SP `tlog-checkpoint` signed note under origin `gatehouse.coproduct.one/<tenant>/v1`, trust-first signature-line matching. Store (`gatehouse-store`, SQLite) makes `leaves` append-only by trigger, rebuilds the tree on read, stores checkpoints only for reached sizes, keeps a quarantine flag per key (36, 239). Ingest pre-verifies with the same `authenticate` before append (`control/src/lib.rs:7-11`). **Witnesses: none** — the crate header says cosignatures "arrive with the witnesses" (A-6 NOT-YET); nucleus's `.gatehouse/trust.toml` has `k = 0, witnesses = []`.

**Refutation** (`control/src/lib.rs:412 refute`, A-8 DECIDED): only two *verified* claims about the same `(gate_def, scope, tree, env)` that disagree void a signer; the re-run is ingested first as a claim in its own right. `voids_the_signer` (61-77) splits internally-inconsistent rejections (digest, signature, schema, chain, net probe) from policy mismatches (binding, tier, window), after commit `112bea6` found that a wrong `env` in a query string was "a remote quarantine primitive". `scripts/check-spot-check.sh` exercises this end to end with a gate that reads outside its scope.

## 5. NOT-YET rows (`docs/assurance/not-yet.md`)

- **A-6** witnessed inclusion under k-of-n: no witnesses (milestone 4).
- **A-7** verify-or-run ≡ running under determinism: `VerifyOrRun.lean` not written; Det never proved for TESTED gates, only *measured* by the spot-checker.
- **A-9** reads nothing outside scope: selection proved (`lean/Scope.lean#selectPruned_eq_select`) and materialized (`gatehouse-git#materialize`); missing the executor that confines the rest and the access-log half. Today: k8s restricted pod, read-only root, deny-all NetworkPolicy, canary (`gatehouse-agent/src/lib.rs:150 pod_spec`, `236 network_policy`); `caps_enforced` is a `/proc` read. Per-pattern `fsWrite`, `cpuMs`, `memMb` are not individually enforced by anything gatehouse controls.
- **A-10** declared environment attested by the executor: no executor (image-by-digest is admitted, not attested; `docs/executor.md:145` platform not enforced).
- **A-15** PROVED gates re-checked by nanoda: spike passed (`spikes/oracle-nat256`), verifier path not built.

Plus doc-only: `docs/hard-cut.md` (nucleus's 50 required contexts → 41 Required + 2 Optional writ gates, ruleset change, rollback); `docs/caches.md` (write-once CAS, externals folded into scope hash; "no sccache, write-twice refusal has no test yet"); Firecracker substrate is an enum value and an M7 milestone. Nucleus consumes gatehouse only in shadow mode (`/home/user/nucleus/.github/workflows/gatehouse-shadow.yml`, informational, fmt/clippy/ci-spec).

## 6. Relation to nucleus's authorization model

**Yes — gatehouse is "principal authorizes bounded agency" applied to CI, with a stronger reliance discipline and a weaker enforcement substrate.** Map onto the five clauses:

1. *Any model*: n/a directly; the "agent" is a shell command, model-free by construction.
2. *Useful real-world work*: the effect is moving `main`; verify-or-run makes it cheap (a hit costs one verification). Only `fmt` is cheap enough to be Required today (`executor.md:142`).
3. *As the principal authorizes*: `Policy.ceiling`, `required`, `queueBudgetMs`, tiers, key validity windows, 2 h job credentials bound to one run. Missing: multiple principals, delegation, approval flows, and — the real gap — **who may change the ceiling**. The ceiling lives in the PR's own tree; nucleus's `governance_monotone` (`crates/nucleus-policy-kernel/src/lib.rs`, "a policy can only ever get more restrictive") and `chain_attenuates` are exactly the missing check.
4. *Structurally incapable*: the strongest part is at admission (a kernel with `check_sound` decides `Cap ≤ ceiling`) and at reliance (main moves only on verified, included receipts; `gatehouse_github::Conclusion` is never `neutral`; `tree_matches` post-condition). The runtime half is EXTERNAL in `trusted-base.txt:128` — that is nucleus's home turf.
5. *Expand the frontier*: `NOT_YET` shrink-only pin, `UNCOVERED_CEILING=0`, `UNPINNED` shrink-only in the trusted base, certificate cost ceilings, shadow-agreement report with a "vacuous unless a fail was seen" rule (`hard-cut.md:170-188`).

**Nucleus could borrow:**
- *Proof-carrying plans decided by a verified checker.* A `PodSpec`/profile admissibility as `So (admissible_b spec policy) = oh` checked by a ~4.5k-LOC row-local kernel with `check_sound`, instead of trusting `portcullis::PermissionLattice::meet` (`crates/portcullis/src/lattice.rs:60`, a product `Caps×Obligations×Paths×Budget×Commands×Time` with hand-written Rust and Kani harnesses). Note `DelegationScope` (`portcullis-core/src/delegation.rs:172`) compares glob *strings*; gatehouse's `globSubsumes` is the semantic order nucleus lacks.
- *Expectation from stored state, never from the asker* (A-4) for `nucleus-verifier-service`.
- *Receipts-before-reliance, refutation by re-run, signer quarantine* — nucleus signs receipts (`nucleus-receipt`) but nothing re-executes and voids a signer.
- *Tier = min of evidence, never the receipt's own claim* (`effective_tier`) — directly relevant to C9 "verify from the outside" NOT-YET.
- *DECIDED as a status with founding-defect fixtures*, and an *enumerated* trusted base ("assumptions are the complement of what is pinned", `trusted-base.txt:16-19`); nucleus's `check-sandbox-trusted-base.sh` is the membership-test version gatehouse ported and then strengthened.
- *Cost ratchets* (`cost-ceilings.txt`) as a frontier metric: a measurable "how much authorization can be checked per PR".

**Gatehouse could borrow from nucleus:**
- `nucleus-witness` (C2SP `tlog-witness` cosign, k-of-n via `nucleus_lineage::policy`) closes A-6 almost verbatim; both use C2SP signed notes.
- Firecracker + launch measurement (`nucleus-identity::attestation`, `nucleus-node`) for A-10 and the unreachable `LaunchAttested` tier; `nucleus-net-probe`/`nucleus-egress-probe` for the canary; portcullis mediation/IFC as the access-log half of A-9.
- `DelegationChain`/attenuation certificates and `governance_monotone` for multi-principal, monotone ceiling changes.
- CB4A PDP/CDP separation (`nucleus-cred-broker`) for the `secrets` capability, which gatehouse refuses outright today (`SpecError::Secrets`).

**Overlap / duplication:**
- Receipt envelope vendored from `nucleus-receipt` (`types/lib.rs:8-10`); no test pins the copy to upstream (not found).
- Merge-queue model vendored: `lean/CiSpec/{Queue,Capacity}.lean` + `gatehouse-queue/src/queue.rs` duplicate nucleus `ci/lean/CiSpec` and `crates/ci-spec` (`queue/src/lib.rs:3-6`, "vendored verbatim"). Two proofs of T4-T7 to keep in sync.
- Ledger / gates-can-fail / trusted-base tooling: ports (`xtask/src/{ledger,gates,trusted_base}.rs:3`).
- Transparency log: `gatehouse-tlog` re-implements checkpoint/signed-note rather than depending on `nucleus-lineage`; key-id sig-type bytes differ (0x01 log vs 0x04 cosignature) but are compatible by spec.
- Identity: `gatehouse-ca` is hand-rolled Ed25519 credentials with SPIFFE-style URIs; `nucleus-identity` has SPIRE/X.509 SVIDs. `trust.toml` declares `trust_domain = "spiffe://gatehouse/nucleus"` without any SVID issuance.
- Capability lattice: `Cap` (8 fields, CI-specific) vs `PermissionLattice`/`DelegationScope`; same idea, different vocabularies, neither proven to embed in the other.

**Bottom line.** gatehouse has proved the *authorization-checking* clause (well-typed plan ≤ ceiling, verified checker, small enumerated TCB) and built the *reliance* clause (signed, logged, refutable receipts) to DECIDED; it has not built the *confinement* clause and has no witnesses, no attestation, one shared bearer for writes, and a ceiling nobody signs. Nucleus is the mirror image. The unifying move for the North Star is to let nucleus's substrate execute gatehouse's proof-carrying plans and let gatehouse's kernel+ledger discipline decide and record nucleus's authorizations.
