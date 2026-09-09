# Clause 4 verification — "structurally incapable of exceeding that authorization"

Method: read every cited file/line in nucleus and gatehouse; grep for counter-evidence
(existing mechanisms under other names). No builds/tests run.

## G1 — agent process outside the boundary  → CONFIRMED (critical)
- run.rs:1022-1062 exactly as described: `claude --print --allowedTools ... --disallowedTools ... --settings <hook> --dangerously-skip-permissions --permission-mode bypassPermissions`.
- mediation.rs:1-36: "the hook is the boundary"; exit-2 PreToolUse contract.
- constants.rs:36 `HOOK_BINARY_NAME = "nucleus-claude-hook"`; `ls crates | grep hook` → nothing. run_hook (run.rs:408-445) errors "not found" → fails closed but dead.
- README.md:145 admits the runner is coupled to one vendor CLI and the hook lives in a private repo.
- Tier 2 (run_enforced, run.rs:664-746): CLI + nucleus-mcp still on host; only pod is in VM.
- Counter-evidence considered: PodSpec has `workload: Option<WorkloadSpec>` (nucleus-spec lib.rs:114, 905-935) run in-guest under FM-5 distinct uid via WorkloadLaunch::admit — so the *slot* to put the agent inside exists; but nothing in `nucleus run`/`shell` uses it (build_pod_spec sets `workload: None`). north-star.md:587 states "The agent process must not have ambient authority" — the repo's own goal, unmet.
- Verdict: confirmed. Impact critical stands.

## G2 — fine-grained PDP inside the guest → CONFIRMED (critical), minor precision
- guest-init main.rs:49 PROXY_BIN; exec_proxy at 856-877 execs proxy as PID-1 successor.
- broker_perform.rs:19-27 literal: FlowTracker/taint ceiling/trifecta/egress allowlist "live in the tool-proxy inside the guest, and none of them is reachable from here"; broker.rs:105-125 pdp_decide only checks level_for(op)!=Never.
- workload.rs:263-282: uid boundary in a shared guest kernel.
- Precision: host does more than "netns + Never": net.rs applies iptables IP/port allow rules from `NetworkSpec.allow` and a dnsmasq allowlist resolver (start_dns_proxy, only when dns_allow non-empty). No TLS termination, no host+method+path ACL on host. Finder's claim is fair at the level of "fine gates".
- Verdict: confirmed.

## G3 — Tier 1 not a principal boundary → CONFIRMED (high)
- run.rs:474-540: per-run HMAC secrets go into proxy argv (`--auth-secret`, `--approval-secret` visible in /proc/<pid>/cmdline!) and into mcp.json env (write_mcp_config 880-935). No 0600 chmod found.
- build_local_pod_spec (636-662): network: None, workload: None. Children: env_clear only; hardening.rs:16-22 seccomp/Landlock "deliberately deferred".
- web_fetch_policy.rs:38-41,80-83: empty allowlist → Ok(()) (allow-all); no private/link-local block (only a test at :388 asserting redirect to metadata blocked *given an allowlist*).
- Wire mismatch confirmed: nucleus-mcp main.rs:94-96 `RunRequest{command:String}` posted to /v1/run; tool-proxy main.rs:898 `RunRequest{args:Vec<String>}` no serde alias. nucleus-mcp has no tests dir.
- approve_operation main.rs:4319-4350 ignores headers, records ActorIdentity::Unknown.
- Ed25519 approver path exists in Tier 2 (auth.rs:399-490, main.rs:387) — finder acknowledges. Local mode does not use it.
- Verdict: confirmed; even slightly understated (secrets on argv).

## G4 — widening paths dead/unbound, no revocation → PARTIALLY-ADDRESSED (high)
- mediation.rs:161-190 and main.rs:3105-3125: #2406 admitted in code. Confirmed.
- escalate.rs: EscalationGrant minted, logged, returned; grep "kernel" in escalate.rs → 0 hits; EscalationGrant not referenced anywhere else in tool-proxy. Confirmed dead.
- kernel.rs:1747 grant_approval, 1905 issue_approved_token: unauthenticated &mut self; issue_approved_token called from HTTP handlers main.rs:2933,3142,3400 (after ApprovalRegistry consume / identity policy). Confirmed.
- escalation.rs:153 has_attestation = !is_empty; verify() 257-270 = expiry+monotonicity only. Confirmed.
- verifier.rs:319 "No revocation checking for now". Confirmed. Only lockdown_client.rs coarse fleet lockdown.
- COUNTER-EVIDENCE on the ceiling claim: run_gate.rs `levels_for` (line ~58) derives `ceiling` from `state.pod_cert.effective` when present and `requested` from the on-disk policy; they are equal only for an honest pod, and a test pins that a policy above the certificate is denied. reviews/north-star-certificate.md:146-148 ("dormant") is stale relative to run_gate.rs. So WithinDelegationCeiling is NOT vacuous by construction — it is vacuous only because there is no escalation channel to raise `requested`.
- Verdict: partially-addressed (core holds; ceiling sub-claim inaccurate). Impact high.

## G5 — heuristic classifiers on enforcement path → PARTIALLY-ADDRESSED (high→medium-high)
- command.rs:949-956 basename(git)&&argv[1]=="push" etc. Confirmed.
- command.rs:544-552 join then CommandLattice.can_execute re-splits with shell_words (portcullis command.rs:216-236). Confirmed. (Mitigant: refuse_bad_argv #2573 runs on the real argv before join, and execution uses argv not the joined string, so the joined string is only for the *policy* check.)
- attack_corpus.json:14-15 two known_gap vectors. Confirmed.
- SECURITY_TODO §3/4/7 Partial; production-delta.md:41 bash -c bypass. Confirmed.
- COUNTER-EVIDENCE: nucleus-mcp-guard (classify.rs:36-40) is NOT on any enforcement path — no crate depends on it (only a doc comment in broker_perform.rs:49). It is a standalone audit tool. That bullet should be dropped.
- Verdict: partially-addressed; impact high stays for the argv-inference part (git push authority is decided by string shape).

## G6 — proved ≠ shipped → CONFIRMED (high), small count corrections
- DecidePureProofs.lean:10-21 hand model; FunsExternal.lean:31-42 hand-written le/ge; extracted/mod.rs:1-17 mirrors bound by parity tests. Confirmed.
- Kani: 121 `#[kani::proof]` (finder said 118). kani-nightly.yml runs 5 portcullis harnesses on push+PR+schedule; kani-spawn-boundary.yml runs 1 (proof_argv_check_fail_closed) per PR → 6/121 per PR, not 5/118. KANI-STATUS.md:13-60 confirms 12/17 ck-kernel never terminate and portcullis full job dies (exit 143).
- verified-claims.md:36-37 & 124 still say "Kani harnesses run in the Mutation Testing job" — ci.yml Kani jobs are inventory/ratchet only. Confirmed stale.
- FORMAL_METHODS.md:238-246 JSON protocol / session persistence "Not verified". Confirmed.
- portcullis-effects lib.rs:573 `ShellEffect::run(&str, _authority)` shell_words-splits and spawns without spending authority; GitEffect commit/push `_authority` likewise. Confirmed. mediated-set.md:119 Sandbox::exists "Signature-blocked, not judged safe". Confirmed.
- Verdict: confirmed.

## G7 — in-VM children unconfined, egress backstopped, no covert-channel treatment → PARTIALLY-ADDRESSED (high)
- pod_mgmt.rs:390-400 hard-coded Unsandboxed + TODO. Confirmed. hardening.rs deferrals. Confirmed.
- mediated-set.md rows 5,6,10 `backstopped-only`. Confirmed. net.rs:320 no DNS proxy when dns_allow empty. Confirmed.
- attestation.rs:10-18 "NOT hardware-rooted". north-star.md C9 NOT-YET. sandbox-trusted-base.txt:52 UNPINNED, 62-64 EXTERNAL. Confirmed.
- Covert channels: north-star.md excludes "timing, cache, microarchitectural" explicitly at the claim level; production-delta FM-5 row lists timing/size/proxy-response as residual. So "unaddressed" = "explicitly out of scope", fair.
- COUNTER-EVIDENCE: `boot-a-real-pod` IS a required status check (quickstart-boot-noop.yml:1-10 exists precisely so it can be required; production-delta FM-5 row says blocking gate on x86_64). check-egress-probe.sh:8's "not a required check" comment is stale or refers to the egress sentinel specifically. aarch64 job exists but inert. Finder's "not required" is partially wrong.
- Verdict: partially-addressed. Impact high.

## G8 — gatehouse: checker without enforcer; unsigned mutable ceiling → PARTIALLY-ADDRESSED (medium)
- trusted-base.txt:128 "no executor yet; v1 seccomp/Landlock/netns/kubelet EXTERNAL". Confirmed.
- gatehouse-agent lib.rs:150-232 emits k8s Pod (runAsNonRoot, drop ALL, RuntimeDefault seccomp, readOnlyRootFilesystem, resource limits cpu/mem/ephemeral-storage) + deny-all NetworkPolicy. runner lib.rs:86-99 caps_dropped = CapEff==0 read. Confirmed.
- controld put_plan (lib.rs:956-982): bearer-guarded, requires ≥1 Required gate, no monotonicity/ceiling check, no signature. Confirmed.
- COUNTER-EVIDENCE: memMb and cpus ARE individually enforced per gate through k8s limits (mem_mb → limits.memory, cpus → limits.cpu, disk_mb → ephemeral-storage). cpuMs (CPU-time) and fsRead/fsWrite path patterns are not. Finder's "per-pattern fsWrite/cpuMs/memMb not individually enforced" overstates memMb.
- Verdict: partially-addressed. Medium.

## Missed gaps
M1. Approval receipts do not bind the approver. approve_operation (tool-proxy main.rs:4319-4350) discards `_headers` and records `actor: ActorIdentity::Unknown`, even on the Ed25519-signed tier; `x-nucleus-actor` is a client-supplied string (auth.rs:196-199) not derived from the verifying key. Authorization events are unattributable in the audit chain — "who authorized this widening" is not evidence.
M2. Tier-1 secrets on argv: run.rs:518-528 passes `--auth-secret`/`--approval-secret` as process arguments → world-readable /proc/<pid>/cmdline, worse than the env exposure the finder cites.
M3. Standing approvals: /v1/approve accepts arbitrary `count` (main.rs:923-931 default; 4343) and TTL up to MAX_APPROVAL_TTL_SECS; a single grant can be a bulk pre-authorization — no principal-visible cap on count.
M4. Operator env downgrades on the node: `NUCLEUS_ALLOW_UNATTESTED_EGRESS=1` (production-delta row 9) turns the fail-closed egress-fence attestation into a WARN, and `NUCLEUS_ALLOW_LOCAL_DRIVER` (node main.rs:105) enables a no-VM driver. These are env-string kill switches on structural properties, not signed operator decisions recorded in the pod's attestation.
M5. LLM-side budget is delegated to the vendor CLI (`--max-budget-usd` run.rs:1046), i.e. enforced by the very process outside the boundary; nucleus enforces only per-command AtomicBudget and spawn ledger.
M6. Per-command timeout in the HTTP run path is `#[allow(dead_code)] // Reserved` (tool-proxy main.rs:906-907); a run can hold the sandbox indefinitely up to pod timeout (availability, not authority — minor).
