# Clause 2 verification — "as much useful real-world work"

Method: static reading of /home/user/nucleus and /home/user/gatehouse; every cited
file:line re-read; greps for alternative implementations before accepting a gap.
No repo file modified, no cargo run.

## C2-G1 — exec path dead on the wire  → CONFIRMED (critical)
- nucleus-mcp/src/main.rs:93-96 `struct RunRequest { command: String }`; tool schema
  875-882 `properties.command`; POST at 1170-1181 sends it to /v1/run.
- nucleus-tool-proxy/src/main.rs:896-909 `struct RunRequest { args: Vec<String>, stdin,
  directory, timeout_seconds }` — no `#[serde(alias)]`, no custom Deserialize; grep for
  `"command"` in the proxy finds nothing. `timeout_seconds` is `#[allow(dead_code)]`.
- Counter-evidence looked for: the Python SDK (sdk/python/nucleus_sdk/client.py:88-95)
  and the proxy's own `--mcp` server (tool-proxy/src/mcp.rs:62, 553-563) both use
  `args` — they work; only the nucleus-mcp binary that `nucleus run` spawns
  (run.rs:189 default "nucleus-mcp", 547/690 resolve_binary_path) is mismatched.
- Correction to the finder's metachar claim: shipped profiles compile to
  `CommandLattice::permissive()` (profile.rs:437) which sets `allow_metacharacters:
  true`. That does not rescue shell work because /v1/run is argv-only (no shell) and
  `default_blocked_rules` (command.rs:581-616) blocks `bash|sh|zsh|fish -c`,
  `python -c`, `bun/lua/Rscript -e`. So pipes/redirects are unreachable either way.
- hardening.rs:16-17 states seccomp-bpf and Landlock are NOT shipped; Tier 1 children
  have env-clear + no-new-privs only.
- pod_mgmt.rs:388-400 `ContainmentMode::Unsandboxed` inside the VM: confirmed verbatim.
- Ledger has no live `run` row (rows 3-6, 10, 12, 14+ TODO), consistent with it never
  having been exercised end-to-end through nucleus-mcp.

## C2-G2 — credentialed real-world APIs unreachable → CONFIRMED (critical)
- Only credentialed route: /v1/egress/{name}/{*path} (main.rs:2096-2099);
  egress.rs:225-260; PerformRequest fields operation/target/justification/
  idempotency_key/path/body (egress.rs:323-332) — POST body only, no method, no ACL.
- CredentialedEgressSpec fields: name, upstream, credential_env, header, value_prefix
  (nucleus-spec lib.rs:791-823). No path/method/budget fields. Broker
  (nucleus-cred-broker) has no method/path/budget code (grep).
- nucleus-mcp tools: read/write/run/web_fetch/glob/grep/web_search + 5 pod tools; the
  only "egress" string is an error message (main.rs:542). SDK, openclaw plugin: no
  egress call. `credentialed_egress` appears in two design docs only, no example YAML.
- No git credential helper / GIT_ASKPASS / credential.helper in either repo (grep).
- docs/design/spiffe-github-agent-identity.md §1.4 explicitly says git push should be
  "one more CredentialedEgressSpec" — design, not built.
- OIDC crates (nucleus-github-oidc, nucleus-fly-oidc) validate INBOUND identity
  tokens; they do not mint outbound cloud credentials. AWS env forwarding in node
  main.rs:1570-1576 serves only the `remote-audit` S3 sink feature.
- cart.rs consumers: nucleus-identity tests and nucleus-commerce-conformance only.
- reject_bypassable_upstreams (egress.rs:152-180) confirmed: host cannot be both on
  net allowlist and a credentialed upstream.

## C2-G3 — effect vocabulary frozen → CONFIRMED (high), one citation corrected
- ifc_ops.rs:23-52 (13 ops) and 220-262 (19 SinkClass) confirmed. profile.rs:84-125
  CapabilitiesSpec has exactly 13 fields; no extensions/tools/sinks map.
- `CapabilityLattice.extensions` exists (capability.rs:157) and tool_surface.rs builds
  on it, but the only writer is nucleus-cli/src/manifest.rs:347 (offline manifest
  tool); the node mints no surface; consumer is nucleus-mcp-guard which `nucleus run`
  never launches (grep in nucleus-cli finds only doc comments).
- classify.rs:36-40 substring rules confirmed.
- portcullis/src/mcp_mediation.rs has a generic McpMediator + ToolClassifier
  (check_tool(name, subject) at :524) — zero consumers outside lib.rs. No /v1/tool
  route in the proxy.
- Correction: the finder cites the deprecated `Kernel::decide(op, subject)`
  (kernel.rs:1125); the live path is `decide_term(ActionTerm)` which DOES carry
  `verified_scope.allowed_paths/allowed_operations` (run_gate.rs:325-329) and the
  cert has SinkScope {allowed_paths, allowed_hosts, allowed_git_refs}
  (certificate.rs:454-467). That is path/host/ref scoping, not tool-argument caveats,
  and the node mints `SinkScope::unrestricted()` at every site
  (pod_authority.rs:351,419,448). Conclusion unchanged: no argument-level constraint
  a principal can set. Browser: no code (grep hits are OIDC/agent-card docs).

## C2-G4 — session-wide taint ceiling → CONFIRMED (high)
- sink_consequence_split.rs:3-5 verbatim. exposure_core.rs:207-240 verbatim.
  kernel/ifc.rs:126-130 env default false; only other mention is tests_main.rs:1051;
  no PodSpec/profile field named graded.
- Nuance: flow_graph.rs:882-897 scans per-node `effective_label(id, op)` and
  declass_scopes (1202-1210) can lower one node's label for a sink mask, so labels
  ARE per observation node. But `session_adversarial` is a sticky bool and any live
  adversarial node taints every op — no per-argument provenance. Finder's point holds.
- scoreboard.json keys: formal_verification, rust_craft, sandboxing, hygiene — no
  utility/ceiling metric. defense.py:96,110 raise NotImplementedError. Confirmed.

## C2-G5 — approvals → REFRAMED (high)
- #2406 confirmed by mediation.rs:161-190 and main.rs:3106-3118 (two independent
  comments) and ledger row 2 (write 403 approval_required), row 2c TODO.
- ActorIdentity::Unknown at approve (main.rs:4341-4350) confirmed; counter grant
  (count:1, mcp main.rs:1363-1369) confirmed; EscalationGrant has no consumer beyond
  escalate.rs; portcullis/src/escalation.rs has no apply/attenuate fn.
- REFUTED sub-claim: "unsigned post_approve can never succeed in Tier 2". The node
  fronts every Firecracker pod with `SignedProxy` using
  `ApprovalSigning::Ed25519(state.approval_signer)` (node main.rs:2723-2737), adds
  drand round + actor headers, and returns THAT listen address as `proxy_addr`, which
  nucleus-cli consumes (run.rs:690-698, 836-837). So nucleus-mcp's unsigned request
  is signed in transit. The blocker is #2406 (grant unread on the HTTP path) and the
  missing approver identity (node's `proxy_actor` is the actor, not a principal), not
  the signature.

## C2-G6 — path scoping → CONFIRMED (high)
- profile.rs:208-215 "Empty means all allowed"; no profile YAML has `allowed:`.
- session_mint.rs:35-41 deferral text verbatim; :161 asserts allowed_paths.is_empty().
- delegation.rs:48-66 glob_covers hand-rolled; only file mentioning it; no Kani/Lean.
- glob handler 3806-3820 checks only `directory`. Ledger rows 2/2b verbatim, still FAIL.
- Gatehouse ci.writ:44-45 subsetGlob/globSubsumes; writ-kernel lib.rs:716
  prim_glob_subsumes "refuses what it cannot derive" — confirmed.
- Partial mitigation: enforcement plumbing for allowlists exists (SinkScope →
  VerifiedScope → ActionTerm in run_gate.rs:325-329); nothing populates it.

## C2-G7 — network → CONFIRMED (high), gatehouse claim narrowed
- net.rs:318-320 returns None on empty dns_allow; 983-1009 IPv4-once resolution; no
  TTL/re-resolve (grep); IPv6 disabled (net.rs:738-739, 1847). dnsmasq `no-resolv`,
  no `server=` (net.rs:2005-2012) — static map. No REDIRECT/transparent proxy (grep).
- web_fetch_policy.rs:38-41, 80-83 empty = allow; docstring at 176-188 "Empty
  allowlists mean open"; no private-range/loopback/metadata block (grep); the
  169.254 test at 388 only passes because dns_allow is non-empty.
- run.rs:653 `network: None` for Tier 1. profile.rs has no network field.
- Gatehouse: prelude hermeticCap (ci.writ:76-77, used at :132) requires net None and
  zero secrets; gatehouse-agent lib.rs:137 refuses secrets. BUT lib.rs:138-144 ADMITS
  `Net::Pinned` with an allowlist and 243-249 emits a k8s NetworkPolicy egress for it,
  so the k8s agent already has a pinned tier; only the writ prelude and the nucleus
  executor (docs/executor.md:88) are net-less. Finder overstated "every gate".

## C2-G8 — long-running / multi-session → CONFIRMED (medium)
- pod_authority.rs:314 ttl = timeout_seconds; session_mint.rs:72; no renew (grep).
- production-delta.md snapshot row "Not started (guard landed)" verbatim.
- ProvenanceMemorySet::new() in-process (main.rs:497-498, 1905); no disk persistence
  in nucleus-provenance-memory (only witness/token serialisation); no memory tool in
  nucleus-mcp (tool list).
- AgentSpawnEffect NotImplemented (effects lib.rs:767-777); strip_requested_workload
  (pod_mgmt.rs:707-713); main.rs:1413-1416 "most pods run no workload" — a sub-pod is
  proxy-only. docs/temporal.md is a sketch; nucleus-client is HMAC signing only.
- Perf numbers match docs/perf/agent-tool-call-isolation.md:20-28.

## Missed gaps
1. No edit/patch, delete, rename or mkdir over the mediated surface. Routes
   (main.rs:2096-2116) are read/write/run/web_fetch/glob/grep/web_search/memory/
   approve/escalate/declassify/egress; `Sandbox` has create_dir/remove_file/remove_dir
   (sandbox.rs:473-615) unexposed; `edit_files` capability maps to the whole-file
   write tool (run.rs:1073-1077). Deleting needs `run rm`, and `rm -rf` is in the
   default blocklist (command.rs:69).
2. `run` is one-shot request/response with no streaming, PTY, or background job:
   RunResponse {status, stdout, stderr} (mcp main.rs:1185-1190; proxy run_command
   3251+; command.rs:655-770 spawn_with_timeout). Dev servers, watchers, REPL-driven
   work, and anything longer than the policy timeout cannot be delegated.
3. web_fetch MIME allowlist is text/structured only (web_fetch_policy.rs:13-17;
   NetworkSpec.mime_allow) — binaries (archives, wheels, images, PDFs) cannot come
   through the mediated fetch; with G7 this closes dependency acquisition entirely.
4. Tier 2 is Linux+KVM only (README:284); the container driver injects credentials as
   raw env vars and has no broker transport (production-delta "Credentials in the
   guest spec": Partial). On macOS/no-KVM hosts the credentialed path of G2 does not
   exist at all and secrets are exposed — the envelope is platform-dependent.
5. Approver identity is the node, not a principal: SignedProxy signs every
   /v1/approve it receives with the node key and `proxy_actor` (node main.rs:2723-2737,
   signed_proxy.rs:228-240). Anyone able to reach the proxy port is an approver;
   no principal-scoped approver exists — belongs with G5.
6. The portcullis `McpMediator` (mcp_mediation.rs) — the crate's stated "any MCP
   client gets enforcement for free" — has no runtime consumer; the default runner
   mediates only nucleus's own 7 tools (ties to G3).
