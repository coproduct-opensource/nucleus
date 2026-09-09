# State of the art, Sept 2026: formal verification of systems code and human-oversight/delegation UX for agents

Research report for the Nucleus north star ("any model ... as much useful real-world work as its principal is willing to authorize ... structurally incapable of exceeding that authorization ... continuously expand the frontier"). Read against the five clauses: (1) model agnosticism, (2) breadth/depth of mediated effects, (3) expressiveness of authorization, (4) enforcement completeness and small machine-checked TCB, (5) measurement and ratchets. Method: 20 web searches; primary sources fetched where the egress proxy allowed (GitHub-hosted READMEs/CHANGELOGs), otherwise search-result excerpts of the primary source. Local repos (nucleus `FORMAL_METHODS.md`, `KANI-STATUS.md`, `scoreboard.json`; gatehouse `docs/assurance/gatehouse-assurance.md`) were read to make the conclusions concrete, but nothing was modified.

## Thread A: formal verification of systems code, 2025-2026

### A1. Rust-to-Lean via Charon/Aeneas
Aeneas translates a subset of safe Rust (via Charon's MIR/ULLBC extraction) to pure functional code with Lean and HOL4 as the mature backends; it now supports partial functions, extrinsic termination proofs, monadic-program tactics, closures lowered to plain structs with `Fn` impls, and Charon's lifting of associated types to parameters (unlocking iterator-style traits). Documented limits remain material: no `return` inside nested loops or `break`/`continue` to outer loops; generics instantiated with `&mut`; no unsafe or concurrency (pending separation-logic work); external crates extracted incompletely; monomorphisation and hand-written "model" code for trait-bound functions; and Lean toolchain drift across Aeneas, Hax, Mathlib and downstream libraries that must be aligned by hand (Charon is pinned by commit in `charon-pin`; Lean by `lean-toolchain`). A May 2026 experience report on running AI provers over an Aeneas pipeline confirms the same failure modes: finite supported subset, termination-checker misses on generated recursive definitions, and the pipeline being brittle to toolchain motion. Nucleus already hits exactly these edges (`FORMAL_METHODS.md`: Aeneas errors on `bool`-field structs and 13-variant `repr(u8)` enums; lattice functions are hand-curated extracts from the Aeneas output because full output does not compile under Lean 4.28). This is the 2026 norm, not a Nucleus-specific failure.

### A2. Verus
Verus (SMT-backed, linear ghost types) is the systems-scale workhorse: VerusBelt (PLDI 2026) gives the first semantic soundness proof for a substantial Verus subset (cells, invariants, resource algebras, storage protocols, lifetimes, concurrency). LLM-driven proof synthesis is now credible at system scale: VeruSAGE reports >80% fully automated proofs on system-scale tasks with a plan-then-act agent; VeruSyn synthesised 6.9M verified Rust programs for fine-tuning; KVerus verified modules of the Asterinas kernel and contributed to the Verus stdlib. Verus is queued for inclusion in verify-rust-std CI. Trade-off versus Aeneas: Verus proofs live in-source and check fast but produce no reusable Lean object; Aeneas yields kernel-checked Lean artefacts you can compose with Mathlib and export for independent re-checking.

### A3. Kani and verify-rust-std
Kani 0.63-0.67 (June-Nov 2025) added `#[kani::quantifier]`, loop contracts including `for`/`while let` and `modifies`, autoharness deriving `Arbitrary` for structs/enums and handling references, solver selection (bitwuzla/cvc5/z3), `--prove-safety-only`, and contract/stub support in trait impls. The Rust Foundation/AWS verify-rust-std campaign (paper covering through March 2026): 16,748 auto-generated harnesses, 11,970 verified against Kani's UB classes, 989 contract-verified proofs, 4,645 harnesses for unsafe fns, >450 PRs from >=21 external contributors, four tools in CI (Kani, ESBMC, VeriFast, Flux) and four under review (Verus, Creusot, KRust, RAPx); 8-10 of 29 challenges resolved. It also drove function contracts into rustc as an experimental feature. Open problems named by the authors: generic functions, compiler intrinsics, relaxed-memory concurrency, and keeping proofs synchronised with a moving codebase. Nucleus's `KANI-STATUS.md` (12 of 17 harnesses never terminate because they build `BTreeSet<String>`) is a textbook instance of the "BMC over unbounded heap strings" wall; the campaign's answer is contracts plus stubbing, not more time.

### A4. Lean 4 proof maintenance
Lean ships monthly (4.30.0 May 2026 with Reservoir bulk artifact fetch, `.ltar` archives, `lake cache`, and a `fixedToolchain` option; 4.33.1 Aug 2026 stable). Mathlib (1.9M lines) documents its maintenance regime: deprecation aliases with dates, linters as first-line feedback, import-graph hygiene for parallel builds, and custom triage tooling. Proof-repair-from-compiler-feedback (Feb 2026) and Lean agent skill packs exist but are assistive. Practical consequence: pin the toolchain, cache via Reservoir, run an axiom audit and sorry/vacuity gate per commit (gatehouse's `scripts/lean-axiom-audit.sh` and nucleus's `sorry_admit`/`vacuous_lean` scoreboard counters are the right instruments), and treat every toolchain bump as a tracked migration.

### A5. Proof-to-code ratios and verified capability machines
seL4 remains the reference point: ~8.7-10 KLOC of C against roughly 200K lines of Isabelle for functional correctness (about 20-25 proof lines per C line; ~1M lines across all proof layers), 12 person-years for the original proof, and the observation that effort scales roughly with the square of spec size. The 2025 seL4 Summit reported verified-configuration coverage on Arm going from 13% to 90% of platforms in one year with marginal proof cost near zero for the 23rd platform: proof reuse via parameterisation is the scaling story. Verified capability machines matured: Morello-Cerise (PLDI 2025) proves strong encapsulation for the full sequential Arm Morello ISA in Iris/Rocq; Cerisier (2026) extends the program logic to attested enclave code; VeriCHERI does exhaustive RTL-level checking. For a runtime, the lesson is that capability confinement proofs are done against a small machine model plus a logical relation for arbitrary untrusted code; Nucleus's `nucleus-ifc-kernel`/`portcullis-core` proofs should be framed the same way (known kernel code plus universal statement over unknown pod code).

### A6. Proof-carrying authorization and verification-guided development
PCA (Appel-Felten 1999; Bauer-Schneider-Felten; PCFS; Grey) puts the burden of proof on the requester: the policy is a logic, the request carries a proof, the reference monitor only checks. Modern descendants: Biscuit (public-key, offline attenuation, Datalog checks), Macaroons (HMAC caveats, no proof-of-possession), and 2026 IETF drafts applying them to agents: `draft-niyikiza-oauth-attenuating-agent-tokens` (append-only, monotonic narrowing along delegation chains with proof of possession) and `draft-prakash-aip` (Invocation-Bound Capability Tokens; JWT/Ed25519 single hop, Biscuit chained mode for multi-hop). Cedar (AWS) is the exemplar of verification-guided development: an executable Lean model roughly 10x smaller than the Rust production code, proofs of validator soundness, and differential random testing of Rust against the model; 4 bugs found by proof, 21 by DRT/PBT. Nucleus's `nucleus-pca` crate and its Lean-extracted lattice are aligned with both lineages; the Cedar pattern (small Lean model, DRT against Rust) is the practical bridge for the parts Aeneas cannot extract.

### A7. Verified transparency: SCITT, Sigstore, in-toto/SLSA
SCITT architecture is at draft-22 (Oct 2025, Standards Track, not yet RFC), defining Signed Statements, Receipts, Transparent Statements, Registration Policies and Transparency Services over COSE_Sign1 and COSE receipts; SCRAPI is the companion API draft. Sigstore Rekor v2 (tile-based, Trillian-Tessera/tlog-tiles) reached GA; it drops SignedEntryTimestamps and requires clients to include RFC 3161 timestamps in bundles, with periodic log rotation (a 2026 instance replaces 2025). SLSA provenance stays on in-toto attestations in DSSE envelopes. The stable pattern in all three: signed claim -> inclusion in append-only Merkle log -> cosigned checkpoint by independent witnesses -> offline-verifiable receipt with freshness. Gatehouse's ledger already states this as A-5/A-6 (fresh cosigned checkpoint, k-of-n witnesses) with A-6 still NOT-YET.

### Thread A conclusion: what a world-class runtime should adopt
1. Two-tier verification with an explicit correspondence story: Aeneas-extracted Lean for the pure kernel (lattice, IFC, receipt verification) and a Cedar-style small hand model plus differential random testing for everything Aeneas rejects. Publish the extraction ratio (nucleus scoreboard: 85%) and the DRT coverage as first-class metrics.
2. Kani for bounded UB/contract checking on the Rust that carries the effect boundary, using contracts and stubs to escape unbounded-heap blowups; report harness counts split into verified/never-terminated, exactly as `KANI-STATUS.md` now does.
3. Independent re-check of exported Lean environments under a second kernel with an axiom allowlist (gatehouse A-15) so "PROVED" is portable, not a CI colour.
4. TCB accounting in seL4/gatehouse style: enumerate opaque primitives and axioms from source, pin each line, and let the unpinned count only shrink (gatehouse A-20).
5. Receipts as PCA objects: every effect verdict is a signed, log-included, freshness-bound statement whose verifier is the small proved checker; align formats with COSE/SCITT receipts and in-toto/DSSE so external relying parties need no Nucleus code.
6. Proof-maintenance discipline as CI: toolchain pins, Reservoir caching, sorry/vacuity/axiom gates, drift check between committed and freshly extracted Lean, and a migration playbook per Lean release.

## Thread B: human oversight and delegation UX for agents

### B1. Approval fatigue is now measured, not hypothesised
2026 practitioner literature converges: when agents prompt before every tool call, reflexive approval rates reach ~97% and reviewers stop reading command strings; automation bias compounds fatigue so a plausible-looking mistake is waved through. Recommended mitigations are structural: escalate on risk signals not action categories; route by reviewer expertise; SLA-bounded approval timeouts that fail closed rather than pile up; pre-approval of a category of actions within a session; time-boxed holds so the agent abandons rather than waits. The coding-agent market has converged on a three-stage filter: allowlist (roughly 80% of calls, obviously safe), sandbox (roughly 15%, risky but containable), classifier or human judgment (roughly 5%: network, destructive disk ops, state-mutating MCP). Auto/classifier modes became defaults in major CLIs in Aug 2026, always layered over an OS sandbox and network restrictions because "any single layer can be talked around."

### B2. Intent-bound, task-scoped, attenuating authority
Three strands agree on shape. (a) Human-Anchored Intent-Bound Delegation (FAI, 2026): agent authority is ephemeral and task-scoped, tied to a verifiable human principal, with runtime intent checks. (b) Deterministic pre-action authorization (arXiv 2603.20953): a policy engine decides every tool call before execution, with sliding-window per-agent aggregate state to catch sequence-based structuring attacks (many small allowed actions composing into a disallowed one) and formalised delegation chains. (c) Compositional authorization overlays (arXiv 2606.03518) layering delegation and scope semantics over OAuth. Token mechanics: OAuth 2.1/OIDC for the human principal, SPIFFE/WIMSE for the workload, and attenuating tokens (Biscuit/Macaroon lineage, IETF drafts above) for chains, with monotone narrowing and proof of possession. Agentic commerce (Mastercard Agent Pay Agentic Tokens, Visa's June 2026 rollout) productised the same envelope for money: spend cap, merchant restriction, validity window, and per-purchase confirmation flag, all set when authorization is granted, not per action. Research prototypes (PAuth, CXI) show that deriving the minimal authorised operation set from the natural-language task blocks injected operations on AgentDojo with zero false positives; ST-WebAgentBench shows policy-compliant success is ~38% lower than raw completion, i.e. the safety/utility gap is measurable.

### B3. Regulation: EU AI Act Articles 12/14, NIST, US and Singapore
EU: Annex III high-risk obligations apply from 2 Aug 2026; Article 12 requires automatic lifecycle logging that supports traceability and post-market monitoring (Tier 2 penalties, EUR 15M or 3%); Article 14 requires oversight that is meaningful, including that overseers can understand capabilities and limits, remain aware of automation bias, interpret outputs, decide not to use or override/reverse, and interrupt or stop the system. No harmonised technical standard exists yet: prEN 18229-1 ("AI trustworthiness framework Part 1: logging, transparency and human oversight", targeted Q4 2026) and ISO/IEC DIS 24970 (AI system logging) are the drafts to track, and prEN 18229-1 is understood to address agentic multi-step architectures explicitly. Practitioner guidance for agents: log inputs, outputs, decision points, timestamps, operator interactions, tool use and full execution paths across systems, tamper-evident, with the Article 19 minimum six-month retention. NIST: CAISI launched the AI Agent Standards Initiative (17 Feb 2026) with three pillars (industry-led standards via ISO/IEC JTC 1, open protocol development with NSF, fundamental research on agent security/identity/interop evaluation); the NCCoE concept paper (5 Feb 2026) proposes adapting OAuth 2.0/2.1, OIDC and SPIFFE/SPIRE for agent identity and authorization on behalf of a human principal; COSAiS control overlays on SP 800-53 and the Cyber AI Profile (Dec 2025) supply control language; red-teaming guidance followed in March 2026. US law: a California statute bars defendants from arguing the AI autonomously caused harm; a June 2026 executive order directs DOJ enforcement against misuse of agents; Senator Warner's AI AGENT Act discussion draft (29 June 2026) would require consumer agents on large platforms to operate under transparent, documented, scope-limited, revocable user authorization with records of actions, FTC-enforced with NIST standards. Singapore IMDA's May 2026 discussion paper places responsibility on the humans and entities behind agents and emphasises mandate scope and traceability. Common denominator across jurisdictions: named human principal, documented scope, revocability, and tamper-evident action records.

### B4. Measurement of the safely-delegatable envelope
Benchmarks now exist for the propensity side: FelonyBench (2026, spec complete, implementation pending) measures unprompted authorization-boundary crossing across nine categories (sandbox escape, filesystem, credentials in five tiers, privilege escalation, network, persistence, exfiltration, prompt injection, environment tampering) and reports attempted vs successful violations, protected-resource access, exfiltration, persistence and false-reporting rates alongside task completion. AgentDojo (97-124 tasks, 629 injection tasks) and AgentHarm cover the induced side; AgentAuditor targets human-level safety evaluation. The public sandbox-escape incident in an evaluation harness (OpenAI/Hugging Face, 2026) made "successful violation rate under a real runtime" a reportable number.

### Thread B conclusion: what a world-class runtime should adopt
1. Mandate objects, not prompts: a signed task envelope granted once, carrying principal identity, scope (paths, hosts, tools, operations), budget (USD, seconds, calls), validity window, chain depth, and an explicit list of action classes that still require confirmation. This is the commerce "agentic mandate" generalised, and matches the Warner draft's scope-limited/revocable language.
2. Least authority by default with structured escalation: the runtime derives the minimal operation set from the envelope; anything outside is denied or escalated with a risk-scored, expertise-routed, SLA-bounded approval that fails closed on timeout. Approvals extend the envelope (a new signed attenuation), never a one-off bypass, so the audit trail stays a chain.
3. Sequence-aware enforcement: sliding-window aggregate limits per agent and per chain to defeat structuring; budgets are a lattice dimension enforced in the same proved kernel as capabilities (nucleus's `PermissionLattice` wraps budget/time but these are not yet in Lean; that is the gap to close).
4. Monotone attenuation along delegation chains with proof-of-possession tokens (Biscuit-class), depth limits, and revocation that voids a signer's downstream grants (gatehouse A-3 semantics applied to agents).
5. Article 12/14-shaped records by construction: one signed, hash-chained record per kernel decision including refusals and deferrals, naming the authority chain (nucleus `article-12-record-keeping.md` already does this), retained >= six months, exportable in a SCITT/in-toto-compatible form, plus a first-class stop/override primitive whose invocation is itself logged.
6. Ratchets: publish per-release the FelonyBench-style violation rates under the runtime, the policy-compliant-success gap, the fraction of tool calls auto-approved vs escalated vs denied, and median time-to-approval; a growing envelope means auto-approved share rises while successful-violation rate stays zero. Add these to the scoreboard beside proof metrics so clause (5) has numbers.

## Cross-cutting synthesis for Nucleus and gatehouse
The two threads meet in one object: the receipt. A signed decision record that (a) is produced by a checker small enough to extract to Lean, (b) carries the mandate it was decided under, (c) is included in a witnessed tile log with a fresh cosigned checkpoint, and (d) is verifiable offline by a relying party using only public formats, satisfies PCA, SCITT, Article 12, and the "structurally incapable" clause at once. The remaining gaps in the local ledgers (gatehouse A-6 inclusion, A-7 verify-or-run, A-9 scope confinement, A-10 environment attestation, A-15 independent kernel re-check; nucleus's non-terminating BTreeSet harnesses and un-extracted budget/time dimensions) are exactly the items the 2026 state of the art shows how to close.

## Sources
- https://github.com/AeneasVerif/aeneas
- https://lean-lang.org/use-cases/aeneas/
- https://aeneasverif.github.io/newsletter/2025/05/15/aeneas-newsletter.html
- https://arxiv.org/html/2605.30106 (Rust-to-Lean pipeline with AI provers, experience report)
- https://pldi26.sigplan.org/details/pldi-2026-papers/82/VerusBelt-A-Semantic-Foundation-for-Verus-s-Proof-Oriented-Extensions-to-the-Rust-Ty
- https://arxiv.org/abs/2512.18436 (VeruSAGE)
- https://arxiv.org/html/2605.03822v1 (KVerus)
- https://arxiv.org/html/2606.17374 (Verifying the Rust Standard Library)
- https://rustfoundation.org/media/how-the-rust-standard-library-verification-contest-scaled-past-manual-proof-engineering/
- https://github.com/model-checking/verify-rust-std/blob/main/README.md
- https://github.com/model-checking/kani/blob/main/CHANGELOG.md
- https://arxiv.org/abs/2607.01504 (Kani: A Model Checker for Rust)
- https://lean-lang.org/doc/reference/latest/releases/v4.30.0/
- https://arxiv.org/html/2508.21593v1 (Growing Mathlib)
- https://arxiv.org/pdf/2602.02990 (Learning to Repair Lean Proofs from Compiler Feedback)
- https://sel4.systems/Verification/proofs.html
- https://cacm.acm.org/research/sel4-formal-verification-of-an-operating-system-kernel/
- https://dl.acm.org/doi/10.1145/3729329 (Morello-Cerise, PLDI 2025)
- https://doi.org/10.1145/3808287 (Cerisier)
- https://dl.acm.org/doi/10.1145/319709.319718 (Appel-Felten, Proof-carrying authentication)
- https://www.cs.princeton.edu/research/techreps/337 (A Proof-Carrying Authorization System)
- https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing
- https://lean-lang.org/use-cases/cedar/
- https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
- https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/
- https://blog.sigstore.dev/rekor-v2-ga/
- https://github.com/sigstore/rekor-tiles
- https://docs.sigstore.dev/about/bundle/
- https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/
- https://www.ietf.org/archive/id/draft-prakash-aip-00.html
- https://github.com/eclipse-biscuit/biscuit/blob/master/DESIGN.md
- https://nhimg.org/community/agentic-ai-and-nhis/ai-agent-approvals-and-alert-fatigue-what-teams-are-missing/
- https://waxell.ai/blog/ai-agent-approval-workflows
- https://www.buildmvpfast.com/blog/approval-fatigue-agent-permission-ux-2026
- https://inventivehq.com/blog/ai-coding-cli-sandbox-approval-modes-compared
- https://harness-guide.com/guide/classifier-permissions/
- https://www.thefai.org/posts/human-anchored-intent-bound-delegation-for-ai-agents
- https://arxiv.org/html/2603.20953v1 (Before the Tool Call: deterministic pre-action authorization)
- https://arxiv.org/pdf/2606.03518 (Overlaying Governance: compositional authorization for delegation and scope)
- https://www.entrust.com/blog/2026/05/ai-agent-authorization-delegation-zero-trust
- https://eco.com/support/en/articles/14839409-ai-agent-spend-controls
- https://www.axios.com/2026/06/10/visa-chatgpt-agents-commerce
- https://artificialintelligenceact.eu/article/14/
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-12
- https://www.helpnetsecurity.com/2026/04/16/eu-ai-act-logging-requirements/
- https://www.etuc.org/sites/default/files/page/file/2025-11/AI%20standardisation%20Inclusiveness_Newsletter11.pdf (prEN 18229-1)
- https://arxiv.org/pdf/2502.10036 (Automation bias in the AI Act)
- https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure
- https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd
- https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ai-agent-standards-20260416-csa-style/
- https://www.bakermckenzie.com/en/insight/publications/2026/06/united-states-legal-accountability-for-ai-agents
- https://www.dlapiper.com/en-la/insights/publications/2026/07/senator-warner-discussion-draft-on-securing-ai-agents-top-points
- https://www.imda.gov.sg/-/media/imda/files/about/emerging-tech-and-research/artificial-intelligence/agents-legal-responsibility.pdf
- https://github.com/MLOpsNYC/FelonyBench/tree/main
- https://arxiv.org/pdf/2510.06445 (Survey on agentic security; AgentDojo/AgentHarm/ST-WebAgentBench figures)
- https://arxiv.org/pdf/2506.00641 (AgentAuditor)
