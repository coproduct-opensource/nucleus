# Clause 4 gap analysis — "structurally incapable of exceeding that authorization"

Date: 2026-09-08. Static reading of /home/user/nucleus and /home/user/gatehouse; every
file:line below was opened and read, not taken from the maps. No builds run, nothing modified.

## What "structural" means here

For clause 4 a runtime is structural when: (a) every side effect crosses a boundary the
agent cannot argue with; (b) the component that decides sits *outside* the boundary it
polices; (c) the only paths that widen authority are signed by a principal and consumed by
the same verified checker; (d) the checker that ships is the checker that was proved; (e) the
whole trusted base is enumerated, small, and verifiable by the principal. Nucleus is strongest
on (a) behind the tool-proxy (sealed effect home, cap-std, discharge-gated `Authority`) and
weakest on (b), (c) and (d). Gatehouse is the mirror image: strong on (d) at admission, no (a).

## What is genuinely structural today (credit where due)

- `portcullis-effects` sealed home: `RealEffects` unconstructible outside the crate, every
  effect method takes `Authority` by value, minted only from a `DischargedBundle` that only
  `preflight_action` produces; agent-path raw-spawn allowlist is empty
  (`scripts/mediation-allowlist.txt`), grep + dylint gates.
- Tier 2 substrate: Firecracker + jailer + netns `-P DROP` + seccomp-applied check + read-only
  root + in-guest egress/workload probes; FM-5 workload posture (distinct uid, `close_range`,
  env classifier refusing unknown `NUCLEUS_*`), proved over an extracted relation.
- `LatticeCertificate` chain: per-hop Ed25519, hash chain, `leq` re-verified per hop, sink
  scope, expiry, PoP, sealed `VerifiedPermissions`; guest holds no root key.
- Honest ledgers (north-star ledger, sandbox-trusted-base, mediated-set.md, KANI-STATUS.md).

## The eight gaps, ranked by how much safely delegatable agency closing them would unlock

### G1 (architectural, critical, large) — The agent process lives outside every structural boundary

Verified: `crates/nucleus-cli/src/run.rs:1022-1062` spawns the vendor CLI on the *host* with
`--dangerously-skip-permissions --permission-mode bypassPermissions`, relying on
`--allowedTools`, `--disallowedTools` (`constants.rs:20-21`) and a `PreToolUse` exit-2 hook
(`crates/nucleus-cli/src/mediation.rs:1-30`, which says plainly "the hook is the boundary").
`constants.rs:29` hardcodes `AGENT_CLI_BIN = "claude"`; `constants.rs:31-36` names a hook crate
(`nucleus-claude-hook`) that does not exist in the tree. In Tier 2 (`run.rs:664-746`) the agent CLI
and `nucleus-mcp` still run on the operator host and talk HTTP into the VM — the VM confines
*tool execution*, not the model. So in every tier the model process holds the operator's full
ambient host authority, and the only thing between it and the host is a third-party binary's
flag semantics. A model that ignores hooks, a CLI update that adds a built-in, or any other
vendor's harness simply is not confined. This also breaks clause 1: the boundary is vendor-
specific by construction.

SOTA: every 2026 sandbox provider (E2B, Codex cloud, K8s Agent Sandbox, Anthropic hosted
execution) runs the *agent* inside the microVM/gVisor boundary; Sandlock's split-TCB and
"Delegation Without Trust" (arXiv 2609.00267) both state the criterion: a fully compromised
agent cannot exceed delegated authority — which requires the agent to be inside the fence.

Direction: make the agent harness (any vendor CLI/SDK loop, or an open-weight runner) the
pod's `workload`, running under the FM-5 distinct uid inside the guest, with vsock/loopback to
the proxy as its only exit; `nucleus run` spawns nothing on the host except the pod; the
PreToolUse/allowedTools mechanics become optional UX adapters (a `PreToolUse`-compatible hook
endpoint, per the protocols report) rather than the boundary. Ratchet: `bypass_sites` must go to 0
by deleting the host launch, not by relabeling it.

### G2 (architectural, critical, epic) — The fine-grained decision point runs inside the boundary it polices

Verified: guest-init execs the tool-proxy as PID-1's successor inside the guest
(`crates/nucleus-guest-init/src/main.rs:49,856-877`). `crates/nucleus-node/src/broker_perform.rs:19-27`
states it outright: "`FlowTracker`, the session taint ceiling, the lethal-trifecta guard and the
egress allowlist all live in the tool-proxy inside the guest, and none of them is reachable
from here." The host's own PDP (`crates/nucleus-node/src/broker.rs:105-125 pdp_decide`) checks
only `policy.capabilities.level_for(op) == Never`; the netns `-P DROP` is the only other host-side
fence. The in-guest separation between the workload and the proxy is a uid boundary in one
shared guest kernel (`crates/nucleus-tool-proxy/src/workload.rs:263-282`); a guest-kernel LPE or a
proxy bug hands the workload the proxy's full authority and every fine gate disappears, leaving
"any host on the allowlist, any op not `Never`". The Lean/Kani investment is therefore protecting
a component the adversary can reach.

SOTA: Firecracker's own design doc — all guest egress is untrusted and filtered at the host;
the isolation report's smallest credible TCB puts the *effect supervisor* (policy lattice,
budgets, revocation, TLS-terminating egress proxy, credential broker) on the host and proves
that; Sandlock's static-kernel-policy + narrow supervisor split.

Direction: relocate `Kernel::decide` + flow graph + egress/URL allowlists + budget to a host-side
supervisor in `nucleus-node` (extending the existing broker vsock channel) that fronts a
TLS-terminating egress proxy (host+method+path ACL, so `bash -c curl` becomes mediated rather
than backstopped), an always-on DNS forwarder, and file/exec brokers; the guest proxy becomes a
thin client carrying only the public attenuation token. Keep the guest copy as defense in depth.
Then the theorem "no sink reachable without discharge" is about code the adversary cannot touch.

### G3 (implementation, high, medium) — Tier 1 is not a principal boundary at all

Verified: `run_local` (`crates/nucleus-cli/src/run.rs:474-540`) generates `auth_secret` and
`approval_secret`, writes them into `mcp.json` in `std::env::temp_dir()` via `write_mcp_config`
(`run.rs:880-935`: `NUCLEUS_MCP_AUTH_SECRET`, `NUCLEUS_MCP_APPROVAL_SECRET`,
`NUCLEUS_MCP_SANDBOX_TOKEN`), and hands the approval secret to the process the model drives. Model,
MCP server, tool-proxy and every `run` child share one uid, so any allowed `run` command can read
the file or `/proc/<pid>/environ` and self-approve at `/v1/approve`
(`crates/nucleus-tool-proxy/src/main.rs:4319-4350`, recorded as `ActorIdentity::Unknown`). Children
get only `env_clear()` (`crates/portcullis-effects/src/lib.rs` ~640) — no Landlock/seccomp/netns
(`crates/nucleus/src/hardening.rs:16-22` defers them; `HostHardened` is never set by the proxy).
`build_local_pod_spec` sets `network: None` (`run.rs:640-660`), and empty allowlists mean allow-all
(`web_fetch_policy.rs:38-41,80-83`) with no private/link-local block (only a test mentions
169.254.169.254). Separately, the default exec path is dead by wire mismatch: `nucleus-mcp` posts
`{"command": String}` (`crates/nucleus-mcp/src/main.rs:94-96,1170-1181`) while the proxy expects
`{"args": Vec<String>}` (`crates/nucleus-tool-proxy/src/main.rs:891-905`) — fail-closed, but it
shows no conformance test binds the two halves.

SOTA: Claude Code / Codex / Gemini local modes all ship bwrap+seccomp(+Landlock)/Seatbelt and an
egress proxy for local runs; Sandlock shows the unprivileged split.

Direction: Tier 1 children run under Landlock (paths from `PathLattice`) + seccomp + a user
netns whose only route is the proxy; workload uid distinct from the runtime uid (reuse the FM-5
`WorkloadLaunch::admit` plan on the host); replace the shared HMAC approval secret with the
Ed25519 approver-key path Tier 2 already supports, held by the principal not the model's env;
default-deny private/metadata ranges in `check_dns_allowlist`; add an MCP<->proxy wire
conformance test and fix `command`/`args`.

### G4 (implementation, high, large) — Every authority-widening path is either dead or unbound to a verified principal signature; there is no revocation

Verified: `crates/nucleus-tool-proxy/src/mediation.rs:161-190` — `RequiresApproval` from
`http_kernel_decide` returns before the only code that consults `ApprovalRegistry`, so "an operator
who grants an approval here gets a 200 and no effect (#2406)"; `main.rs:3105-3125` confirms and
notes a double consume. `crates/nucleus-tool-proxy/src/escalate.rs:140-240` validates policy, mints
an `EscalationGrant`, records and returns it — the string "kernel" does not occur in the file; the
grant is never applied. `crates/portcullis/src/kernel.rs:1747 grant_approval` and `:1905
issue_approved_token` are unauthenticated `&mut self` methods. `crates/portcullis/src/escalation.rs:153`
`has_attestation` is a non-empty check and `verify()` (`:257-270`) checks only monotonicity and
expiry — attestation bytes are never signature-verified; the "revocation propagation" docstring
(`:177`) has no code. `grep revok` finds nothing in `certificate.rs`/`token.rs`; X.509 CRL/OCSP are
skipped (`nucleus-identity/src/verifier.rs:319`, `tls.rs:319`). The only substitute is fleet
lockdown (`nucleus-node/src/main.rs:3688`). `run_gate.rs:37-44` sets `ceiling == requested` so the
`WithinDelegationCeiling` obligation is vacuous (north-star-certificate.md:146-148).

SOTA: UCAN's delegation/invocation split (possession is not authority); Biscuit third-party
blocks + per-block revocation ids; AP2 Cart Mandate (a second, narrower principal-signed object
auto-issuable only inside the Intent's predicates); AuthZEN AARP; PORTICO epoch-bound grants.

Direction: one `Escalate` channel: an approval is a signed *extension block* appended to the
pod's certificate chain by an approver key that is not the workload key (a Biscuit-style
third-party block), re-verified by `verify_certificate` and consumed by `preflight_action`, so
`requested` genuinely comes from the task and `WithinDelegationCeiling` fires; delete
`grant_approval` from every HTTP-reachable path; give each block a revocation id, ship a
deny-list gossiped over the existing witness-gossip layer, and make `SpiffeTraceChain.attestation`
either verified or removed.

### G5 (implementation, high, medium) — Heuristic classifiers decide what an effect *is* on the enforcement path

Verified: `crates/nucleus/src/command.rs:945-956` — git push / commit / PR are
`basename(argv[0]) == "git" && argv[1] == "push"` etc., so `git -C x push`, `make push`, `xargs`, a
script, or any wrapper falls into generic `run_bash`; `command.rs:552` joins argv with spaces and
`portcullis/src/command.rs:216` re-splits it with `shell_words` before `can_execute`; mcp-guard maps
tools to source/sink roles by case-insensitive substring (`nucleus-mcp-guard/src/classify.rs:36-40`).
`crates/nucleus-tool-proxy/tests/attack_corpus.json` records two `known_gap` vectors: injected
web content reaching `AgentSpawn` and `CloudMutation` because `sink_required_authority()` defaults
them to `NoAuthority`. SECURITY_TODO §3/§4/§7 remain "Partial"; `docs/production-delta.md`
"Command exfiltration detection: `bash -c 'curl ...'` bypasses ... Firecracker network policy is the
backstop". Whether an action needs `git_push` authority is decided by string shape, which is the
opposite of structural.

SOTA: PACT / AUTHGRAPH enforce at the *argument* level with provenance contracts; Type-directed
privilege separation turns strings into a closed set of typed values; ActPlane enforces on
indirect execution paths via BPF-LSM; Gemini CLI's `argsPattern` shows the schema approach.

Direction: a typed effect vocabulary in the tool schema — `GitPush{remote, ref}`,
`CreatePr{repo, base}`, `Http{method, host, path}` — so the *effect type* is chosen by the tool the
agent called, not inferred from argv; the residual `run` path is enforced by the OS (Landlock paths;
seccomp-notify `execve` inspection of the real argv at exec time, Sandlock-style) rather than by
parsing; give every action sink an authority floor to close the two `known_gap` vectors; add a
differential fuzz oracle for `CommandLattice` vs an independent parser.

### G6 (measurement + implementation, high, large) — The checker that ships is not the checker that was proved

Verified: `DecidePureProofs.lean:10-21` — the verdict function is a hand model, "NOT the
Aeneas-extracted function"; `generated/PortcullisCore/FunsExternal.lean:31-42` hand-writes
`PartialOrd::le/ge`; `nucleus-ifc-kernel/src/extracted/mod.rs:1-17` — every extracted theorem is
over a `String`-free "byte-faithful mirror" bound by parity tests; `Iter::fold` is an axiom in the
certchain extraction. `kani-nightly.yml:81-85` runs 5 harnesses per PR; KANI-STATUS.md records 12/17
ck-kernel harnesses never terminating and the portcullis full job dying of OOM; `docs/verified-claims.md:36-37,124`
still says harnesses "run in the `Mutation Testing` job" (that job only counts). `FORMAL_METHODS.md:238-246`
lists JSON protocol, session persistence and the compartment side-channel file as "Not verified";
`Kernel::decide` composes the verified lattice with unverified time/budget/path/command matching.
`reviews/north-star-certificate.md:141-153`: the sealed `DischargedBundle` runs *alongside* the legacy
`DecisionToken` stack, base obligation checks are "vacuous on a clean session". `kani-divergence.toml`
records the `extensions: BTreeMap` dims compiled out under Kani. Mediated-set residues remain
(`docs/architecture/mediated-set.md`): `Sandbox::exists` unmediated; legacy `ShellEffect::run(&str)` and
`GitEffect::{commit,push}` in the sealed home never spend their `_authority`
(`portcullis-effects/src/lib.rs:570-585,720-765`); receipts record an *authorised* spend upstream of the
syscall, not a committed effect (production-delta.md "Effect receipts" row).

SOTA: Cedar's verification-guided development (Lean model ~10x smaller + differential random
testing against the shipped Rust); verify-rust-std's contracts/stubs to escape unbounded-heap BMC;
gatehouse's own `check_sound` over the *extracted* row-local kernel with golden differential and
`extraction-drift` checks (`lean-kernel/WritKernelTy.lean:1898`, `scripts/check-kernel-golden.sh`).

Direction: make `Kernel::decide` a thin wrapper over one pure extracted function whose inputs
include time, budget, path and command decisions as data (or, where Aeneas refuses, a Cedar-style
DRT harness that fuzzes `Kernel::decide` against the Lean model and reports coverage as a
scoreboard metric); run every Kani harness in some workflow and rewrite `BTreeSet<String>` harnesses
with contracts/stubs; collapse the dual stack (DecisionToken -> DischargedBundle only); mediate
`exists` and delete the unspent-authority legacy API; add a post-effect "committed" receipt event;
correct the stale claims.

### G7 (implementation, high, large) — Inside the VM, children are unconfined, egress is backstopped rather than mediated, and containment is never attested

Verified: `crates/nucleus-tool-proxy/src/pod_mgmt.rs:390-400` hard-codes `ContainmentMode::Unsandboxed`
with a TODO to derive `MicroVM` from the SandboxProof; `hardening.rs:16-22` seccomp/Landlock for
children deferred; grep finds no Landlock/seccomp in `workload.rs`/`command.rs` beyond comments.
`mediated-set.md` rows 5, 6, 10 (in-shell egress, DNS, raw sockets) are `backstopped-only` by the netns
DROP policy; with no `dns_allow` there is no DNS proxy at all (`nucleus-node/src/net.rs:320`), and
with one, exfil through an *allowed* host or domain fronting is unaddressed — no document in
`docs/north-star.md`, `mediated-set.md` or `SECURITY_TODO.md` mentions covert/side channels
(FM-5 row in production-delta.md lists "covert channels (timing/size/proxy-response)" as residual).
Attestation is "first-party, software ... NOT hardware-rooted" (`nucleus-identity/src/attestation.rs:10-18`);
C9 "verify from the outside" is NOT-YET (`docs/north-star.md:92`); the egress probe boot job is
x86_64-only and "not a required" check (`scripts/check-egress-probe.sh:8`); `sandbox-trusted-base.txt:52`
keeps cgroup-before-workload UNPINNED, `:62-64` Firecracker/KVM/seccomp-filter contents EXTERNAL.
IPv6 is disabled by cmdline rather than modelled (`net.rs:744-757`).

SOTA: Landlock ABI v6/v7 + seccomp-notify (Sandlock) for in-guest children; allowlist-aware DNS
forwarder inside the netns; TLS-terminating egress proxy with path ACLs; RATS/CoCo Trustee and
WIMSE WIT-with-attestation binding VMM/guest/rootfs/policy-blob hashes; `guest_memfd` secret hiding.

Direction: derive `ContainmentMode` from the verified `SandboxProof` tier so `minimum_isolation`
policies can actually run; apply Landlock + seccomp to workload children from the lattice
(paths, no raw sockets); make DNS forwarding always-on and log-mediated; move in-shell egress from
backstopped to mediated via the G2 host proxy; bind rootfs/VMM/seccomp-filter/policy-blob hashes
into a per-pod attestation a principal can verify offline (RATS evidence + the existing
`nucleus verify-attestation`), and make the egress probe a required gate on both arches.

### G8 (architectural, medium, large; gatehouse) — Proved admissibility with no enforcer, and an unsigned, mutable ceiling

Verified in /home/user/gatehouse: `trusted-base.txt:128` "executor sandbox for TESTED gates |
UNPINNED: no executor yet (milestone 4); v1 seccomp/Landlock/netns/kubelet EXTERNAL";
`crates/gatehouse-agent/src/lib.rs:150` `pod_spec` emits a k8s Pod + deny-all NetworkPolicy;
`crates/gatehouse-runner/src/lib.rs:86-99` `caps_enforced` is `CapEff == 0` read from `/proc/self/status`;
per-pattern `fsWrite`, `cpuMs`, `memMb` are not individually enforced by anything gatehouse controls.
The ceiling lives in the tree under test (`.gatehouse/pipeline.writ:9,20`) and `PUT /v1/{tenant}/plan`
(`crates/gatehouse-controld/src/lib.rs:144`) is behind one shared bearer with no monotonicity check.
So `So (admissible_b pipeline policy) = oh` is kernel-checked (`check_sound`, A-12 PROVED) about a
Cap that nothing then enforces, against a ceiling anyone with the bearer can raise. Nucleus is the
mirror: it enforces a lattice at runtime but consumes no proof-carrying plan.

SOTA: PCA (Appel-Felten -> Biscuit); gatehouse's own A-9/A-10 NOT-YET rows; nucleus's
`governance_monotone` (`crates/nucleus-policy-kernel/src/lib.rs:180-209`) is exactly the missing
ceiling check.

Direction: execute gatehouse gates as nucleus pods (prove a `Cap -> PermissionLattice` embedding
so the kernel-checked bound is the lattice the executor enforces; use `nucleus-egress-probe` as the
canary and the FM-5 posture as A-9's access-log half); require the ceiling to be signed by a
tenant key and checked `governance_monotone` on `put_plan`; bind runner receipts to nucleus
launch attestation so `LaunchAttested` stops being an enum placeholder.

## Cross-cutting note

G1 + G2 together are the real shape of clause 4: today the trusted decision logic is inside the
fence and the untrusted model is outside it. Inverting that (agent inside, proved supervisor on
the host) is what would let the lattice's expressiveness (clause 3) and any-model support
(clause 1) be *believed*, and is what every measurement in clause 5 should be run against.
