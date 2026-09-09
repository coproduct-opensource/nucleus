# State of the Art: Structural Defenses and Safety/Utility Measurement for LLM Agents (2024-2026)

Research memo for the Nucleus North Star: *"any model should be able to do as much useful real-world work as its principal is willing to authorize, while being structurally incapable of exceeding that authorization"*, and the claim of *continuously expanding the frontier of safely delegatable agency*.

Method note: 28 web searches; primary-source fetches of arXiv/ACL/NDSS/OpenReview were blocked by the session egress proxy, so paper details come from search-engine extracts of the primary abstracts plus fetched GitHub READMEs (CaMeL, FIDES, Progent, AgentDojo, SecGPT/IsolateGPT, tau2-bench, AdaptiveAttackAgent) and the Microsoft Research publication page. Numbers should be re-verified against the PDFs before being quoted externally.

## 1. The field's converged thesis

Between 2024 and mid-2026 the defense literature converged on a position directly aligned with clause (4) of the North Star: do not try to make the model refuse injections; instead enforce authority *outside* the model with a deterministic monitor, so that a fully prompt-injected agent still cannot exceed delegated authority. "Adaptive Evaluation of Out-of-Band Defenses" (arXiv 2606.26479) names this class "out-of-band" and maps CaMeL, FIDES, Progent, RTBAS and FORGE onto classical Biba integrity, reference monitors and least privilege. "Delegation Without Trust" (arXiv 2609.00267) states the correctness criterion almost verbatim: a correct system is one in which a fully compromised agent cannot exceed the authority explicitly delegated to it. Two negative results frame the ceiling: Abdelnabi and Bagdasarian ("AI Agents May Always Fall for Prompt Injections", arXiv 2605.17634) argue via Contextual Integrity that data/instruction separation can never be complete because an adversary can always construct a context in which a blocked flow looks legitimate, so *detection* cannot be the foundation; and the NAACL 2025 adaptive-attack paper (arXiv 2503.00061) broke all eight in-band defenses it tested at >50% ASR. Both push toward structural enforcement, which is Nucleus's design centre.

## 2. Structural defenses: mechanism, guarantee, limitations

### 2.1 CaMeL (Google DeepMind, arXiv 2503.18813)
**Mechanism.** Dual-LLM plus custom Python interpreter. A Privileged LLM sees only the trusted user query and emits a program; a Quarantined LLM parses untrusted tool output into schema-validated values with no tool access. Every value carries capabilities (provenance and allowed readers); the interpreter checks explicit policies before each tool call. **Guarantee.** Control flow cannot be hijacked (the plan is fixed before untrusted data is read) and data flow is policy-mediated; "provable security" is relative to the policies written. **Results.** 67% AgentDojo task completion under the strict default policy (reject any tool call whose arguments carry untrusted data), 77% with tiered policies vs 84% undefended. **Limitations.** Trusts the initial prompt; no protection against output manipulation or side channels (control-flow-dependent leaks); policies are hand-written per tool; the reference implementation is explicitly a research artifact with likely interpreter bugs. It only covers effects reachable through its interpreter, not a general shell/OS.

### 2.2 FIDES (Microsoft, arXiv 2505.23643)
**Mechanism.** A planner that tracks confidentiality and integrity labels on every variable, deterministically enforces policy at tool-call time, and adds primitives for selectively hiding information (a `query_llm` quarantined sub-model reasons over a variable without exposing its contents to the planner). **Guarantee.** A formal model characterises exactly which properties dynamic taint tracking can enforce, and gives a task taxonomy for reasoning about which task classes are securable at all. Stops all AgentDojo injections with checks on. **Results.** Completes ~16% more tasks than a basic labelled planner with reasoning models, ~24% with prompt tuning. **Limitations.** Taint tracking cannot enforce properties that depend on the semantics of untrusted data; tasks requiring untrusted data to drive control flow remain outside the securable set; explicit-secrecy style policies leave implicit flows.

### 2.3 Progent (arXiv 2504.11703)
**Mechanism.** Programmable privilege control: a JSON-schema DSL over tool names, argument constraints and fallbacks; policies can be authored by hand or generated from the user query by an LLM and updated during the task. **Guarantee.** Least privilege at the tool-call boundary; deterministic denial of any call outside the policy. **Results.** Strong ASR reduction on AgentDojo, ASB and AgentPoison with utility largely preserved; an independent 2026 reproduction found mean ASR fell ~6x (25.8% to 4.2%) and a hand-crafted adaptive attack did not raise it. **Limitations.** LLM-generated policies re-introduce a model in the TCB; argument-level constraints are only as good as the schema; no information-flow tracking, so exfiltration through permitted tools is not addressed; white-box optimised attacks remain untested.

### 2.4 IsolateGPT / SecGPT (NDSS 2025, arXiv 2403.04960)
**Mechanism.** OS-style hub-and-spoke architecture: each app/tool runs in its own process ("spoke") with seccomp filtering, rlimits and domain-restricted networking; a trusted hub routes requests and all inter-spoke communication passes through user-permissioned interfaces. **Guarantee.** App compromise, data theft, inadvertent exposure and uncontrolled alteration are bounded by process isolation, not model behaviour. **Limitations.** The hub's LLM still reads untrusted data; permission prompts to the user scale with interaction count; overhead and utility on standard agent benchmarks not reported.

### 2.5 Design-pattern layer (arXiv 2506.08837; "Prompt Flow Integrity", arXiv 2503.15547; Type-directed privilege separation, arXiv 2509.25926)
The Google/Microsoft/IBM/ETH/EPFL patterns paper gives six constructions (action-selector, plan-then-execute, map-reduce, dual LLM, code-then-execute, context minimisation) with a single invariant: once an agent has ingested untrusted input, it must be impossible for that input to trigger consequential actions. PFI splits the agent into a trusted agent with full plugin access and an untrusted agent restricted to a policy-defined subset. Type-directed privilege separation converts untrusted strings into a closed set of typed values, eliminating injection by construction and extending the securable task set. **Limitation** shared by all: they deliberately give up the ability to solve arbitrary tasks; utility is bounded by the pattern, and the "LLMbda Calculus" (arXiv 2602.20064) shows what is required to prove this formally: a lambda calculus with dynamic IFC and a termination-insensitive noninterference theorem covering planner loops and sandboxed sub-conversations.

### 2.6 Provenance-granular monitors (PACT, arXiv 2605.11039; Agent-Sentry, arXiv 2603.22868; AUTHGRAPH, arXiv 2605.26497)
**Mechanism.** Enforce at the level of tool *arguments*, not whole invocations. PACT assigns semantic roles to arguments (destination, amount, command) and checks that each authority-bearing argument's provenance satisfies a capability contract. AUTHGRAPH aligns a provenance graph with an authorization graph. Agent-Sentry combines a structural classifier over action sequences and per-argument provenance with a deterministic allowlist. **Results.** PACT: 100% security on the three strongest models with 38-46% utility, 8-16 points above CaMeL at equal security. AUTHGRAPH: ASR 0.01 at utility ratio 0.69 vs CaMeL's ASR 0.00 at 0.48. **Limitations.** Provenance inference over natural-language values and contract synthesis are the open bottleneck; Agent-Sentry's residual LLM judge re-enters the TCB.

### 2.7 OS/kernel enforcement (ActPlane, arXiv 2606.25189)
**Mechanism.** A small DSL (e.g. block `git commit` unless `go test` exited 0) compiled to eBPF with IFC labels propagated across process, file and network hooks via BPF-LSM. **Guarantee.** Enforcement holds on indirect execution paths that tool-call interception cannot observe, with 1.9-8.4% overhead. **Limitation.** Kernel-coupled; label vocabulary is coarse; not a substitute for VM isolation. The "Balkanization" SoK (arXiv 2607.05743) notes isolation architectures are almost never evaluated against one another on a shared benchmark and that real-world denylist enforcement fails 69-98% of the time, and that TOCTOU and MCP threats are the same state-validation problem.

### 2.8 Authorization lifecycle work (most relevant to clause 3)
- **PORTICO / "Lingering Authority"** (arXiv 2606.22504): compiles an explicit task contract into initial capabilities, grant rules, closure predicates and global deny rules; grants are opaque, epoch-bound handles removed from the planner interface on closure, with stale-replay rejection before side effects. Zero contract-forbidden effects in evaluated coding-agent runs while controlled grants recover work a fixed envelope blocked.
- **ScopeGate / "Capability Gates Are Not Authorization"** (arXiv 2606.28679): audits LangChain/LangGraph, LlamaIndex and Stripe Agent Toolkit; all provide tool gating, none a deterministic, fail-closed per-call *value* authorization gate. Proposes a five-stage PDP/PEP: scope, authorization, money ceiling, idempotency, default deny.
- **RACG** (arXiv 2606.13884): exposes a high-risk tool only when it lies on a minimal causal path to the goal and is gated by an authorization variable present in state.
- **Delegation Without Trust** (arXiv 2609.00267): four adversaries (confused deputy, token theft/replay, injection-driven privilege escalation, compromised sub-agent); eight requirements; three of four popular frameworks provide no confinement; with defended delegation a compromised sub-agent's reach is bounded by the task and independent of environment size.
- **A Framework for Formalizing LLM Agent Security** (arXiv 2603.19469, Song group): decomposes security into task alignment, action alignment, authorized instruction following, and data isolation, making "the same action can be legitimate or a violation depending on who commanded it" first-class.
- **Data Flow Control / Passant** (Columbia, arXiv 2606.05679): tuple-level provenance policies inside the DBMS for agent-generated SQL, formalised as aggregate predicates over provenance monomials.

### 2.9 Industry practice
Anthropic's Claude Code sandbox (Seatbelt on macOS, bubblewrap on Linux, egress proxy) draws two OS boundaries (filesystem and network) to reduce per-command prompts; OpenAI's Codex CLI uses an approval architecture with similar OS sandboxes. OWASP's Top 10 for Agentic Applications (Dec 2025) lists goal hijack, tool misuse, identity/privilege abuse, supply chain, unexpected code execution, memory poisoning, inter-agent communication, cascading failures, human-agent trust exploitation and rogue agents; a runtime claiming structural enforcement should map each to a mechanism or an explicit non-goal.

## 3. Benchmarks and metrics

| Benchmark | Measures | Key metrics | Notes for Nucleus |
|---|---|---|---|
| AgentDojo (NeurIPS 2024) | 97 user tasks, 629 security cases, 4 suites | benign utility, utility under attack, targeted ASR | De-facto standard for out-of-band defenses; results page is explicitly *not* a leaderboard because coverage is uneven |
| InjecAgent | 1,054 cases, 17 user tools, 62 attacker tools | ASR (base/enhanced) | Older; tool-level only |
| ASB (Agent Security Bench) | 16 attacks, 11 defenses, 10 scenarios, 400+ tools | ASR, refusal, utility | Broadest attack taxonomy; max ASR 84.3% |
| WASP (NeurIPS 2025) | Web agents in sandboxed sites | intermediate vs end-to-end compromise | Finds "security by incompetence" |
| tau-bench / tau2-bench | Policy-compliant tool use with simulated users | pass^k (all k succeed) | Best proxy for "does the agent obey the principal's policy reliably" |
| OS-Harm, AgentHarm, SafeArena | Misuse and injection for computer-use/web agents | harm rate, refusal | Trace-format effects on judging |
| ToolPrivBench (arXiv 2606.20023) | Over-privileged tool selection | OPUR (over-privileged use rate); 6/11 models >30% | Directly measures least-agency |
| ContainmentBench (arXiv 2607.23999) | 504 scenarios, stage-scoped traces | endpoint violations, logged propagation, authorized taint-exposed commits | Shows equal terminal outcomes hide different behaviour (73.5% of pairs differ) |
| ToolPrivacyBench, POLAR-Bench | Purpose-bound disclosure, privacy/utility surface | FOR, SWLR, MT-POI, SMTC; 5x5 policy-by-attack grid | Confidentiality axis, not just integrity |
| SWE-bench (+sandbox) | Coding utility | resolve rate | Utility only; pair with a policy to get "utility under policy" |

**Metric conventions worth adopting.** (a) Report the triple *benign utility / utility under attack / targeted ASR* per model and per policy tier, never a headline number. (b) Report *utility ratio* (utility with enforcement divided by undefended utility), the quantity AUTHGRAPH and PACT use to compare at fixed ASR. (c) Report pass^k for reliability under policy. (d) Report OPUR for least-agency. (e) Publish stage-scoped trace metrics, since ContainmentBench shows terminal ASR hides propagation. (f) Evaluate against *adaptive*, defense-aware attacks (arXiv 2503.00061, 2606.26479); static suites made in-band defenses look strong until twelve fell at >90%.

## 4. Quantifying "how much useful work under constraint": the Pareto view

No published work yet defines an explicit *authorization-utility Pareto frontier* in the sense the North Star needs, but the pieces exist: FIDES's task taxonomy (which task classes are securable by taint tracking at all), CaMeL's two policy tiers (67% vs 77%), PACT/AUTHGRAPH's utility-ratio-at-ASR comparisons, PORTICO's "grants recover boundary work" framing, POLAR-Bench's policy-strictness by attack-strength grid, and cost/accuracy Pareto work from "AI Agents That Matter" (arXiv 2407.01502). The gap a project can own is a benchmark whose x-axis is a *formally specified authorization envelope* (capability set, delegation depth, budget, time bound, approval requirements) and whose y-axis is task completion, with ASR held at zero by construction and verified by adaptive attack, plotted over time and over models.

## 5. What a project claiming to "expand the frontier of safely delegatable agency" should publish

1. **A frontier chart, versioned.** For each release: utility ratio vs authorization envelope size, on AgentDojo (integrity), ToolPrivacyBench or POLAR (confidentiality), tau2-bench (policy compliance), and a coding suite (SWE-bench-style) run inside the runtime. Same model set across releases; the ratchet is "envelope grew or utility ratio rose at ASR = 0".
2. **ASR = 0 by construction, evidenced two ways.** Machine-checked argument (Lean/Kani) that the monitor is complete over the effect surface, plus empirical adaptive-attack runs (AdaptiveAttackAgent-style and hand-crafted defense-aware attacks) showing no executed contract-forbidden effect; report ContainmentBench-style propagation metrics, not only endpoints.
3. **Least-agency metrics.** OPUR-style over-privilege rate and RACG-style "high-risk tool exposed only on minimal causal path" coverage; count of tools exposed per task versus tools needed.
4. **Authorization-expressiveness coverage.** A checklist mapped to clause (3): delegation chains with attenuation, epoch-bound revocable grants (PORTICO), per-call value authorization with money ceilings and idempotency (ScopeGate), multi-principal approvals, time bounds, budgets; each with a benchmark task that is impossible without it and a proof that it cannot be exceeded.
5. **Model agnosticism evidence.** Every metric reported for at least three vendors' models and one open-weight model, because the frontier claim is about the runtime, not the model; the FIDES/CaMeL/PACT results all shift 10-20 points across models.
6. **TCB and coverage disclosure.** Lines of trusted code, which components are LLMs (Progent's policy generator, Agent-Sentry's judge) and therefore inside the attack surface, and which effect paths bypass the monitor (ActPlane's "indirect execution paths"; TOCTOU per the Balkanization SoK).
7. **Cross-architecture comparison.** The Balkanization SoK's headline gap is that isolation systems are never compared on a shared benchmark; publishing Nucleus numbers next to CaMeL, FIDES, Progent, PACT and an OS-sandbox baseline on the same AgentDojo harness would be novel in itself.

## 6. Implications for Nucleus, in one paragraph

The literature's strongest results come from combining three layers Nucleus already gestures at: (i) a value-level provenance/capability monitor at the tool boundary (CaMeL/FIDES/PACT) for integrity and confidentiality of flows, (ii) an authorization lifecycle with revocable, epoch-bound, attenuable grants and per-call value checks (PORTICO/ScopeGate/Delegation Without Trust) for expressiveness, and (iii) kernel- or VM-level isolation (IsolateGPT/ActPlane/Firecracker) so that effects outside the tool API are also bounded. What nobody has published is the measurement layer: a versioned, multi-model, adaptive-attack-validated frontier of utility ratio against authorization envelope with ASR fixed at zero by proof. That is the artefact that would substantiate clause (5).

## Sources

- CaMeL, "Defeating Prompt Injections by Design": https://arxiv.org/abs/2503.18813 ; code https://github.com/google-research/camel-prompt-injection ; commentary https://simonwillison.net/2025/Apr/11/camel/ ; enterprise gap analysis https://arxiv.org/pdf/2505.22852
- FIDES, "Securing AI Agents with Information-Flow Control": https://arxiv.org/abs/2505.23643 ; https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/ ; https://github.com/microsoft/fides
- Progent: https://arxiv.org/abs/2504.11703 ; https://github.com/sunblaze-ucb/progent
- IsolateGPT (NDSS 2025): https://arxiv.org/abs/2403.04960 ; https://www.ndss-symposium.org/ndss-paper/isolategpt-an-execution-isolation-architecture-for-llm-based-agentic-systems/ ; https://github.com/llm-platform-security/SecGPT
- Design Patterns for Securing LLM Agents against Prompt Injections: https://arxiv.org/abs/2506.08837 ; https://simonwillison.net/2025/Jun/13/prompt-injection-design-patterns/
- Prompt Flow Integrity: https://arxiv.org/abs/2503.15547 ; https://github.com/compsec-snu/pfi
- Type-Directed Privilege Separation: https://arxiv.org/abs/2509.25926
- The LLMbda Calculus: https://arxiv.org/abs/2602.20064
- RTBAS: https://arxiv.org/abs/2502.08966
- PACT / Granularity Mismatch: https://arxiv.org/abs/2605.11039
- AUTHGRAPH / Aligning Provenance with Authorization: https://arxiv.org/pdf/2605.26497
- Agent-Sentry: https://arxiv.org/abs/2603.22868
- ActPlane: https://arxiv.org/abs/2606.25189 ; https://eunomia.dev/actplane/
- Lingering Authority / PORTICO: https://arxiv.org/abs/2606.22504
- Capability Gates Are Not Authorization / ScopeGate: https://arxiv.org/abs/2606.28679
- Capability Minimization / RACG: https://arxiv.org/abs/2606.13884
- Delegation Without Trust: https://arxiv.org/abs/2609.00267
- A Framework for Formalizing LLM Agent Security: https://arxiv.org/html/2603.19469v1
- Data Flow Control (Passant): https://arxiv.org/abs/2606.05679
- Provably Secure Agent Guardrail (ePCA): https://arxiv.org/abs/2605.29251
- Prompt Control-Flow Integrity: https://arxiv.org/pdf/2603.18433 ; Context-to-Execution Integrity: https://arxiv.org/pdf/2607.06000
- AI Agents May Always Fall for Prompt Injections: https://arxiv.org/abs/2605.17634
- Adaptive Attacks Break Defenses (NAACL 2025): https://arxiv.org/abs/2503.00061 ; https://github.com/uiuc-kang-lab/AdaptiveAttackAgent
- Adaptive Evaluation of Out-of-Band Defenses: https://arxiv.org/abs/2606.26479
- Balkanization of Execution-Security Research for AI Coding Agents: https://arxiv.org/abs/2607.05743
- Systems Security Foundations for Agentic Computing: https://arxiv.org/abs/2512.01295
- LLM Agents Should Employ Security Principles: https://arxiv.org/abs/2505.24019
- AgentDojo (NeurIPS 2024): https://arxiv.org/abs/2406.13352 ; https://github.com/ethz-spylab/agentdojo ; https://agentdojo.spylab.ai/results/ ; https://invariantlabs.ai/blog/agentdojo
- InjecAgent / ASB / WASP: https://arxiv.org/pdf/2504.18575 ; https://proceedings.neurips.cc/paper_files/paper/2025/hash/1c9818387f5dd0a0bc151214660f059d-Abstract-Datasets_and_Benchmarks_Track.html ; ASB https://axi.lims.ac.uk/paper/2410.02644
- tau2-bench: https://github.com/sierra-research/tau2-bench
- OS-Harm: https://arxiv.org/abs/2506.14866 ; SafeArena: https://arxiv.org/pdf/2503.04957 ; AgentHarm: https://www.giskard.ai/glossary/agentharm-safety-benchmark
- ToolPrivBench / When Lower Privileges Suffice: https://arxiv.org/abs/2606.20023
- ContainmentBench: https://arxiv.org/abs/2607.23999
- ToolPrivacyBench: https://arxiv.org/abs/2606.28061 ; POLAR-Bench: https://arxiv.org/abs/2605.19127
- AI Agents That Matter (cost/accuracy Pareto): https://arxiv.org/pdf/2407.01502
- PromptArmor / defense ranking survey: https://intelscroll.com/perimeter/prompt-injection-defense-state-of-art/
- OWASP Top 10 for Agentic Applications 2026: https://goteleport.com/blog/owasp-top-10-agentic-applications/
- Claude Code sandboxing: https://www.anthropic.com/engineering/claude-code-sandboxing ; https://code.claude.com/docs/en/sandboxing
- Least agency / blast radius: https://predictionguard.com/blog/least-agency-blast-radius-governance-framework-persistent-ai-agents
