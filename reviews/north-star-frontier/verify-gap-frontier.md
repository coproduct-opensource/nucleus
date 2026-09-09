# Verification — Clause 5 "continuously expand the frontier"

Static read of /home/user/nucleus and /home/user/gatehouse (no builds). Every finder citation was
opened; greps across both repos were run before any "missing" verdict. Verdict vocabulary:
confirmed / partially-addressed / already-exists / refuted / reframed.

## Instruments that DO exist (the baseline every verdict is measured against)

| Instrument | Where | What it ratchets |
|---|---|---|
| exemplar scoreboard | `scripts/exemplar-scoreboard.sh`, `crates/xtask/src/scoreboard.rs:18-32`, `.github/workflows/exemplar-scoreboard.yml` | LOWER={permissive_verify,vacuous_lean,sorry_admit,mediation_drift,effect_stubs,unsafe_blocks,stale_verus_dirs}, HIGHER={extracted_proofs,crates_lints_workspace,extraction_ratio_pct,lints_adoption_pct}, plus `_GUARD` anti-Goodhart pairs. **Not in `ci/required-checks.txt` (PINNED=50); no `merge_group` trigger** (line 28 is a comment). Advisory. |
| North Star ledger | `docs/north-star.md` #### Status, `scripts/check-north-star-ledger.sh:47-53`, `scripts/north-star-ledger-ratchet.txt` (CLAUSES=9, NOT_YET=2, DORMANT_GATES=0) | Anchored on the confidentiality sentence ("Whatever an agent workload does … single-use token"). Required check "The North Star status table cannot outrun its wiring". Rows C1–C9 are secrecy/mediation/attestation. |
| CI assurance ledger | `docs/assurance/ci-assurance.md`, `scripts/ci-assurance-ledger-ratchet.txt` (CLAUSES=11, NOT_YET=3) | PROVED/DECIDED/TESTED/NOT-YET for the CI pipeline itself. |
| line/clippy/dep/proof-count ratchets | `scripts/check-line-ratchet.sh`, `check-clippy-ratchet.sh`, `check-dep-ceiling.sh`, kani-nightly "Proof count regression gate", `scripts/formal-numbers.sh` | Hygiene and proof counts. |
| incident replay | `crates/nucleus-ifc/tests/incident_replay.rs` | 4 Denied + 4 Utility + 1 KnownGap cases through `FlowDeclaration::decide()`; `the_suite_measures_both_security_and_utility` requires ≥4 of each. Boolean pass/fail, not a metric. |
| attack corpus | `crates/nucleus-tool-proxy/tests/attack_corpus.{json,rs}` | 13 vectors (11 enforced, 2 known_gap); prints baseline vs enforced bypass rate AND benign false-positive rate (lines 150-160). `known_gap` must remain a gap (line 135-145). |
| OWASP gauntlet / flow red team / identity gauntlet | `crates/portcullis/tests/owasp_llm_gauntlet.rs` (70 tests, REQUIRED via `owasp-gauntlet` job ci.yml:596), `crates/portcullis-core/tests/flow_red_team.rs` (33), `crates/nucleus-identity/tests/security_gauntlet.rs` (47) | Static safety vectors. `docs/production-delta.md:81` counts 162 scenarios. |
| flow replay | `crates/nucleus-flow-replay` (lib.rs ReplaySummary 113-170, main.rs CLI, corpus/{corpus.jsonl,sink-sweep.jsonl,mirror-verdicts.json}) | `replay()` runs `Kernel::decide_term_with_flow` under **`PermissionLattice::permissive()` on purpose** (lib.rs ~175) so only the IFC gate is measured. Tests: `kernel_vs_mirror.rs` (pins divergence vs frozen mirror), `sink_consequence_split.rs` (asserts approval+allowed>0, prints numbers). Not named by any workflow (runs only as part of workspace nextest). |
| adversary probe | `crates/nucleus-adversary-probe/src/main.rs` | 3 stages (pid1 secret theft, rootfs tamper, exfil) each with `attempted=yes`, positive control, CONTAINED/BREACH/INCONCLUSIVE. Per-PR. |
| live-LLM red team | `.github/workflows/red-team-agent.yml` (nightly, single `vars.LLM_MODEL`), `tests/red_team_harness.rs` (SessionScore: total_calls, blocked_calls, leaked/exfiltrated canaries; verdict on exfil only) | Single model, exfil only. |
| perf | `crates/nucleus-perf` (podburst/toolcall/symmetry), `docs/perf/RUBRIC-LEDGER.md` | Manual loop; no workflow references nucleus-perf; rubric rows 15 and 37 (latency gates) TODO. |
| Alignment Tax theorem | `crates/portcullis-core/lean/AlignmentTaxBridge.lean:411 alignmentTaxH1_eq_operational`, `notebooks/alignment_tax_demo.ipynb` | Formal definition of a policy's utility cost (min declassifications = rank H¹). No Rust computes it (grep alignment_tax/AlignmentTax in crates/*.rs → none). |
| gatehouse | `docs/hard-cut.md §3` (shadow report: `ready` needs zero disagreements AND ≥1 observed fail; `vacuous` otherwise), `assurance/ratchet.txt` (CLAUSES=20, NOT_YET=5), `fixtures/plans/cost-ceilings.txt` (NODES/RED/SUB pinned), `docs/executor.md:141-143`, `crates/xtask/src/gates.rs:440` implements the vacuous-shadow check | Referenced patterns exist as claimed. |

Fresh recompute of the scoreboard (`bash scripts/exemplar-scoreboard.sh <scratchpad>/sb-now.json`):
extracted_proofs 6, sorry_admit 26, lean_theorems_GUARD 1466, permissive_verify 13, verify_calls_GUARD 44,
unsafe_blocks 6, crates_total 84, crates_lints_workspace 53, effect_stubs 9. Baseline
(`scripts/exemplar-baseline.json`): extracted_proofs 4, sorry_admit 38, lean_theorems_GUARD 891,
permissive_verify 13, verify_calls 44, unsafe 6, crates_lints 41. Committed root `scoreboard.json`:
permissive_verify **50**, verify_calls 77, lean_theorems 1028, crates_total 72 — does not match what the
script produces today (CI never commits; `contents: read`).

## Verdicts

### F1 — no utility-under-authorization metric — CONFIRMED (critical)
All cited lines check out (scoreboard.rs:18-32; exemplar-scoreboard.sh:53-89; ledger anchor
check-north-star-ledger.sh:47-53; flow-replay ReplaySummary 113-170; sink_consequence_split.rs:139-183
asserts only `approval+allowed>0`; production-delta.md:82 "AgentDojo benchmark comparison | Not started").
Counter-evidence found: (a) `incident_replay.rs` pins a utility half with a non-vacuity floor — but it is
5 boolean cases, not a tracked number; (b) `attack_corpus.rs` prints a benign false-positive rate over 3
benign vectors, never asserted or pinned; (c) the Alignment Tax theorem is a formal definition of the
utility cost of a policy, never computed over shipped profiles. None is a ratcheted or published
utility-under-authorization number. Worse than the finder states: the one instrument (flow-replay) removes
authorization by design (permissive lattice), so it cannot measure the clause-5 quantity at all.

### F2 — AgentDojo bridge dead, red team single-model — CONFIRMED (impact lowered to high)
defense.py:96 and :110 raise `NotImplementedError(_MIRROR_REMOVED)` (verified); pyproject depends only on
agentdojo (+ optional openai as protocol client); no workflow/justfile/Makefile references agentdojo,
portcullis_defense, flow-replay or nucleus-perf; TOOL_MAPPING collapses ~80 tools to 14 operations plus
`synthetic:` sinks (make_divergence_corpus.py:33-77); red-team-agent.yml:95-110 uses one `vars.LLM_MODEL`;
SessionScore scores canaries only. `kernel_vs_mirror.rs` explains the mirror was deleted honestly after
divergence. Impact: high rather than critical — the dead adapter fails loudly (no misleading number) and is
downstream of F1; but it is the only path to a public-suite (utility, security) pair.

### F3 — graded taint is a dormant env flag, "the only utility lever" — REFRAMED (medium)
Accurate: ifc.rs:96 passes `Self::graded_taint_enabled()`; ifc.rs:126-130 reads `NUCLEUS_GRADED_TAINT`,
default false; the only other mention in BOTH repos is the test comment tests_main.rs:1051; grading is by
`default_sink_class(op)` only (exposure_core.rs:716-734). Overstated: it is not the only lever.
`FlowGraph::effective_is_tainted(op)` / `effective_exfiltration_check` (flow_graph.rs:840-895) are
declassification-scope-aware: "a scope admitting `op` can lower a node's contributed integrity" — i.e. the
governor-signed, single-use, sink-scoped declassification token (nucleus-tool-proxy/src/declassify.rs;
C4 TESTED / C5 PROVED in the ledger; `DeclassifySinkScopeExtracted.lean`) is a principal-authorized,
signed, proven, receipted lever that recovers exactly the taint-caused refusals — per value, per sink.
`/v1/escalate` (escalate.rs) is a second principal-authorized widening path. Correct framing: the only
*policy-level default* that trades taint refusals for approvals is the env flag; principal-level recovery
exists but is per-value (governor per release), so it cannot move a utility curve at scale. Argument-
provenance grading (proposal b) is genuinely absent.

### F4 — no denial→policy feedback loop; metrics.rs/pipeline.rs uncalled; no counters — CONFIRMED (medium)
observe.rs:166-199 "Only successful operations contribute" (verified; kernel Decision JSONL with
requires_approval is parsed as not-succeeded, observe.rs:748-762). `metrics.rs` types are re-exported
(lib.rs:299-302) and used by nothing outside portcullis (grep: only tests/examples). `pipeline.rs`
(`permission_gap`/`WeakeningCost`) has no callers in tool-proxy/mcp/cli/node (grep). No
`counter!`/`histogram!`/prometheus in tool-proxy; verdict_sink.rs emits spans only; `/health` exposes only
trace-monitor violation counts (main.rs:2665-2683). Counter-evidence: OTLP spans carry every verdict so an
external backend can aggregate; `/v1/escalate` is an agent-initiated widening request — but nothing
derives a proposal from a denial. Impact medium: aggregation is a backend concern; the missing piece of
substance is the proposal loop.

### F5 — no effect-class onboarding process; frozen vocabulary; dead SinkClasses; lexical stub metric — CONFIRMED (high)
`ifc_ops.rs:14` says "12 core operations", `:81` and `:118` say 13, `capability.rs:22` says 12; enum has
13 (SpawnAgent=12). `WebEffect::fetch/search` and `AgentSpawnEffect::spawn` return `NotImplemented`
(portcullis-effects/src/lib.rs:519,529,774). `effect_stubs=9` = 7 hits in lib.rs (incl. the enum variant
:101, Display :113, two test lines :2244/:2438) + 2 in runtime.rs — 3 real stubs, so the metric is
lexical as claimed. EmailSend/CloudMutation/TicketWrite/SearchIndexWrite/CacheWrite/Proposed-/
VerifiedTableWrite appear only in discharge tables, managed_settings tests, lib.rs tests and the wire
decoder — no live classifier produces them (hook_adapter::classify_sink only reclassifies RunBash and
Write/Edit). Two known_gap vectors (AgentSpawn, CloudMutation NoAuthority) verified. Counter: the closed
`EgressChannel` enum + mediated-set.md parity and the Tier-A theorem over the closed SinkClass enum are a
real inventory for *channels*; nothing equivalent exists per effect class with status.

### F6 — no public delegation scoreboard; friction shows a codegen pod that cannot read/write; no perf gate — CONFIRMED (high)
RUBRIC-LEDGER rows 1/2/2b/2c verified verbatim ("There is no file in the sandbox a codegen pod may read";
write 403 approval_required; /work → sandbox_escape). Rows 15 and 37 TODO. `nucleus-perf` in workspace
(Cargo.toml:3 "Dev-only") and referenced by no workflow/justfile/Makefile. mediation.rs:161-190 (#2406)
verified: a `/v1/approve` grant "gets a 200 and no effect" on the HTTP path; main.rs:3105-3125 confirms.
`nucleus profiles` prints declared levels; `docs/permissions.md` is a guide. `nucleus verify --tier2`
checks one allowed glob, one forbidden read, one admission refusal — not a matrix. No grep hit for
"what can be delegated"/"delegation matrix" in either repo.

### F7 — safety evidence static, single-model, no adaptive/OPUR/stage metrics — PARTIALLY-ADDRESSED (medium)
No adaptive attacker anywhere (grep adaptive/iterat in tests, docs, workflows → none); single LLM_MODEL;
no over-privilege metric (observe.rs operation_counts exists, unused for it). But the finder undercounts
the static side: OWASP gauntlet (70 tests) IS a required check (`owasp-gauntlet` job, ci/required-checks.txt),
plus flow_red_team.rs (33), security_gauntlet.rs (47), incident_replay (9 cases incl. utility half),
envelope adversarial corpus; production-delta counts 162 scenarios. And the adversary probe already records
per-stage `attempted=yes`/blocked with a positive control (3 stages) — not ContainmentBench's stage
semantics, but "nothing records attempted-vs-blocked per stage" is too strong.

### F8 — five-clause North Star has no ledger; extraction metric is a grep of an enum name — CONFIRMED (medium)
check-north-star-ledger.sh:47-53 anchors on the confidentiality sentence (verified). No ledger/vocabulary
for the five clauses (grep "safely delegat" → only portcullis README). NORTH_STAR.md:46 names
`nucleus run --vm`; grep for `--vm`/`"vm"` in nucleus-cli run.rs/main.rs → nothing. `extracted=`
counts `ExtractedKernelChecked` occurrences: exactly 6, all in nucleus-ifc/src/decision.rs (declaration
:358, uses :407/:417, tests :520/:529), while 13 `*Extracted.lean` files exist. Additionally the committed
root scoreboard.json (permissive_verify 50, lean_theorems 1028) disagrees with what the script computes
today (13, 1466).

## Missed gaps

M1. **The only HIGHER-metric ratchet is advisory.** `exemplar-scoreboard.yml` ("exemplar metrics
    ratchet") is absent from `ci/required-checks.txt` (PINNED=50 contexts), has no `merge_group` trigger
    (line 28 is a comment), and is path-filtered. Under the merge queue it does not run; a regression in
    extraction_ratio or a new effect stub cannot block a merge.
M2. **Ratchet slack.** scoreboard.rs:10-11: "the baseline is lowered by a human, never here". Fresh
    numbers vs `exemplar-baseline.json`: sorry_admit 26 vs 38 (12 new sorries land green),
    extracted_proofs 6 vs 4, lean_theorems_GUARD 1466 vs 891 (575 theorems deletable before the guard
    bites), crates_lints 53 vs 41. Contrast the North Star ledger rule (ratchet.txt: "the pin must be
    lowered in the same change that earns the promotion").
M3. **The frontier instrument cannot measure under authorization by construction.**
    nucleus-flow-replay/src/lib.rs `replay()`: "The lattice is `permissive()` on purpose … capability
    denials would be noise." Any utility number from it is utility under *no* authorization. Its corpus
    (corpus.jsonl 155 lines, sink-sweep.jsonl) is pinned by no ratchet and named by no workflow.
M4. **Stale published number.** Root `scoreboard.json` (committed; CI has `contents: read`, no commit
    step) reports permissive_verify 50 / verify_calls 77 / lean_theorems 1028 / crates_total 72; the script
    today yields 13 / 44 / 1466 / 84. The one public "scoreboard" file is not what the instrument produces.
M5. **known_gap population is unpinned.** attack_corpus.rs:135-145 asserts each known_gap stays a gap
    (good) but no ratchet file pins the count (2) shrink-only; incident_replay has 1 KnownGap likewise.
    New known_gap vectors can be added without the visible-event discipline NOT_YET has.
M6. **A formal frontier metric exists and is uninstrumented.** `AlignmentTaxBridge.lean:411
    alignmentTaxH1_eq_operational` (min declassifications to realise capability under an IFC policy) is
    proven and demoed in a notebook; no Rust computes it for the 10 canonical profiles (grep → none).
M7. **No per-release measurement artefact.** `docs/production-delta.md` is "updated with each release"
    by hand; `release.yml` references no scoreboard/ledger/benchmark; nothing versions any number
    release-over-release, so "the envelope grew" cannot be shown even for the containment metrics.
