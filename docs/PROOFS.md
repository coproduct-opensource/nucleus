# What is actually proven — the honesty matrix

> **Read this before you trust any "verified" claim in this repo.**
>
> This is the single source of truth for *the strength of each guarantee*. Every
> row is one of three kinds — **PROVEN** (a machine checks it), **TESTED** (we run
> it and compare bytes), or **ATTESTED/MODELED** (it holds under a *named*
> assumption a machine cannot discharge). The point of the doc is to never let a
> TESTED or MODELED claim get described as PROVEN in a README, a pitch, or a
> commit message. If you find a mismatch, the doc is the bug — fix the claim.
>
> Gap-tracking tags (`G1`–`G7`) refer to the chariot punch-list; this file is
> updated as each gap lands.

---

## The three tiers (what the words mean)

| Tier | Means | Trust model | What could still be wrong |
|------|-------|-------------|---------------------------|
| **PROVEN** | A theorem, machine-checked by the Lean kernel (or Kani's model checker). `#print axioms` is audited. | Trust Lean's kernel + the listed axioms. Nothing else. | The *statement* could fail to mean what you think (spec bug), or the proven model could differ from the running code (the extraction gap — see §5). |
| **TESTED** | Executable code is run and its output is compared to a fixed expected value (golden vectors, proptest, Kani bounded harness). | Trust that the test inputs cover the cases that matter. | Untested inputs. A property that holds on every sampled case but fails on an unsampled one. |
| **ATTESTED / MODELED** | A property stated as a *named hypothesis* (e.g. "SHA-256 is collision-resistant"), or established by hardware/remote attestation, not by our proof. | Trust the named primitive (and, for TEE, the manufacturer). | The primitive being broken; the attestation being forged; the hypothesis not matching the deployed primitive. |

The honest one-liner: **the clearing/settlement/commons math is PROVEN, the cross-language equivalence is TESTED, and the cryptography is MODELED.** No tier is dishonest — but they are not interchangeable.

---

## 1. PROVEN — machine-checked theorems

Two independent Lean trees. Counts are mechanical (`grep '^theorem\|^lemma'`); axiom profiles are audited with `#print axioms`.

### 1a. Economic kernels — `crates/nucleus-econ-kernels/lean/` (mathlib-free, 62 theorems)

Mathlib-free means the *only* axioms these can possibly depend on are `propext` and
`Quot.sound` (plus, in two clearly-marked VCG files, `Classical.choice`). No
`sorry`, no `native_decide` — both are banned in CI (`.github/workflows/econ-lean.yml`).

| Theorem (representative) | What it guarantees | Axioms |
|--------------------------|--------------------|--------|
| `sellerGross_le_price`, `refund_antitone`, `reverse_is_full_refund`, `release_is_full_payout`, `classify_total` | Settlement is conservative and total: the seller is never paid more than escrow, refund grows as delivery shrinks, the verdict is defined on every input. | `propext` |
| `conservation` (commons no-skim, **G2a**) | Routed externality allocations sum to *exactly* the pool — no skim, no dust loss. | `propext, Quot.sound` |
| `opening_unique`, `value_unique`, `profile_unique`, `tamper_changes_commitment` (**G2b**) | Sealed-bid commit→reveal is **binding**: a commitment cannot be opened two ways; tampering changes the commitment. (Under the named SHA-256 injectivity hypothesis — see §3.) | none (pure logic) |
| `vickrey_truthful`, `truthful_price_is_max_others`, `truthful_individual_rationality`, `pigou_vickrey_truthful`, `pigou_zero_tax_is_vickrey` | VCG (and Pigou-adjusted VCG) is dominant-strategy truthful and individually rational; zero tax degenerates to plain Vickrey. | `propext, Quot.sound` |
| `vcg_revenue_non_monotone`, `adding_a_bidder_lowers_revenue`, `inert_padding_preserves_high_revenue` | VCG revenue is non-monotone — a zero-axiom witness (a known-hard property; this is, to our knowledge, a first machine-checked construction). | `propext, Quot.sound, Classical.choice` |
| `credible_reduces_to_set_and_recompute`, `dishonest_outcome_fails_a_check`, `omission_strictly_changes_price` | The credible-clearing reduction: a dishonest clearing **fails a recomputation check** — MISPRICE / FABRICATE / OMIT each leave a detectable trace. | `propext` |
| `requiredBond_antitone`, `requiredBond_deters`, `sybil_no_discount`, `under_collateralized_not_deterred`, `forking_pays_when_understaked` | The reputation↔capital flywheel is **sound and bounded**: proven history substitutes for posted capital, but a Sybil gets no discount and an under-collateralized bonder is *not* deterred. | `propext, Quot.sound` |
| `gov_is_functor`, `stepComp_assoc`, `stepComp_id`, `weakest_link` | The witness→olog `Gov` map is a functor (composition + identity preserved); assurance is weakest-link. | `propext, Quot.sound` |

### 1b. Information-flow control — `crates/portcullis-core/lean/` (Mathlib, 738 theorems)

This tree **uses Mathlib**, so `Classical.choice` is in scope by design. Guarantees here are about the IFC lattice and noninterference, not economics.

| Theorem | What it guarantees | Notes |
|---------|--------------------|-------|
| `integrity_sink_never_admitted` | **Integrity-axis noninterference**: if the effective integrity is already ≤ a joined-in source, and that source non-vacuously fails the sink's ceiling, then over *any* operation sequence the sink is never admitted. | Proven over **Aeneas-generated definitions** (`IntegrityNoninterferenceExtracted.lean`) — i.e. the *extracted* IFC model, not a hand-written one. See §5. |
| lattice laws (`absorption_*`, `adjunction_core`, meet/join) | The capability/derivation labels form a genuine lattice; the decision adjunction is order-correct. | Model-level. |
| `achievability_*`, `alignment_tax_*` | Quantitative noninterference / alignment-tax results over channels. | Model-level. |

---

## 2. TESTED — executable, reproducible parity (not proofs)

These do not produce a theorem. They produce *evidence* that re-running the code yields the expected bytes. They are the bridge between the proven model and the shipped code.

| Mechanism | Where | What it catches |
|-----------|-------|-----------------|
| **Golden-vector seal (G3)** | `crates/nucleus-econ-kernels/tests/golden/*.json` + readers | One JSON single-source pins settlement / commons / VCG outputs across implementations: Lean `decide`-checks (`Nucleus/Golden.lean`, **settlement + commons**), the **Rust** kernel reader (`tests/golden.rs`, settlement + commons + VCG), and the **WASM** reader (`sdks/verifier-js/test/golden.test.mjs`, settlement + commons — run per-PR in `ci.yml`). Foundry/Solidity (`vm.readFile`) + per-vector VCG-in-Lean (VCG's Lean is property-level) remain. Editing any implementation so it diverges from the bytes turns CI red. |
| **Econ-Lean CI** | `.github/workflows/econ-lean.yml` | Builds the whole econ Lean tree (fails on any `sorry` / failing `decide`), **bans `sorry` and `native_decide`** by regex, and asserts `Golden.lean` is regenerable from the JSON (no drift). |
| **Kani bounded model checking** | 114 `#[kani::proof]` harnesses across crates | Overflow/panic-freedom and bounded functional properties on the real Rust (e.g. welfare-overflow). Bounded, not unbounded — see §4. |
| **Property tests** | 21 `proptest!` modules | Randomized differential/invariant checks on the real Rust kernels. Sampled, not exhaustive. |
| **On-chain completeness (G5)** | `examples/marketplace-live/contracts` (Foundry, gated by `.github/workflows/contracts.yml`) | `CommitSet.root` over the revealed sealed-bid set is recomputed in `CredibleSettlement.postClearing` and must equal the `commitmentSetRoot` anchored at `openRound`: an **OMIT**ted, **FABRICATE**d, or altered bid changes the root and reverts on-chain. **MISPRICE** (cleared price ≠ recompute) stays optimistic — bond + `challenge()` → reverse. Each is covered by a Foundry test. The on-chain split is intentional: completeness is cheap keccak (enforced); VCG is too expensive on-chain (optimistic). |

> **The seal is the answer to "does the money-path run the proven function?"** — for the integer kernels it pins the *output bytes* of the shipped code to the same vectors the Lean kernel decides. It is TESTED, not PROVEN: it covers the vectors in the JSON, not all inputs. Closing that last gap for settlement/commons is the extraction work in §5.

---

## 3. ATTESTED / MODELED — the named-assumption floor

These are stated as explicit hypotheses. A machine cannot discharge them; we name them so they are auditable rather than hidden.

| Assumption | Where it enters | Consequence if false |
|------------|-----------------|----------------------|
| **SHA-256 is collision-resistant** (commit is injective over the domain-separated input) | `Scheme.binding` hypothesis in `Sealed.lean`; the commit→reveal binding proof (§1a, G2b) is proven *under* it. | A bidder could open one commitment to two bids. The binding theorem's hypothesis fails; the conclusion no longer applies. |
| **Ed25519 is EUF-CMA secure** | Signature checks in `nucleus-witness-olog` (bond ownership, manifest signing, root attestation). | Forged bonds / manifests / root attestations. The non-custodial slashing argument assumes only the keyholder can produce a valid signature. |
| **TEE remote attestation is sound** (where used as an oracle input) | The externality-oracle RFC's TEE option (Intel TDX / AWS Nitro / Phala). | A compromised or spoofed enclave reports false `units_micro`. This is explicitly flagged as the `TEE.fail` caveat in the RFC; the refereed-dispute path exists precisely so TEE is not the sole root of trust. |

---

## 4. The irreducible floor — what can *never* become a closed proof here

Honesty requires naming what is out of scope of any proof we could write:

1. **Cryptographic hardness** (§3) — collision-resistance and EUF-CMA are conjectures, not theorems. They will always be hypotheses.
2. **Real-world value delivery** — that an agent *actually did the work* (not merely that payment cleared) is a proof-of-task-execution problem; the strongest tools (zkML, TEE attestation, refereed dispute) are TESTED/ATTESTED, never PROVEN, and bottom out in §3 assumptions or an honest-challenger liveness assumption.
3. **Oracle truthfulness of off-chain quantities** — `units_micro` for a real externality is a measurement, not a derivation. We can prove the *routing* of a number is honest; we cannot prove the number matches physical reality without trusting a measurement source.
4. **Kani is bounded** — its harnesses check up to a bound, not for all inputs. A property true to bound `N` but false at `N+1` would pass.

A claim that any of these is "proven" is a claim to watch for and correct.

---

## 5. The model↔code extraction frontier (Aeneas) — G2c

The deepest gap is between a *proven Lean model* and the *running Rust*. Two ways we close it, and where each applies:

- **Extraction (strongest).** Aeneas (`rustc → Charon → LLBC → a functional model → Lean`) emits the model *from* the Rust, so the theorem is about the real code, not a hand-written mirror. **This is already done for IFC**: `integrity_sink_never_admitted` is proven over Charon-generated definitions (§1b). The natural next targets are the **pure-integer econ kernels** — `settlement.rs` (`seller_gross`/`refund`/`classify`) and `commons.rs` (`route_to_commons`) — which sit inside the Aeneas-supported subset (safe, sequential, non-nested loops, integer arithmetic).
- **Golden-vector parity (current floor for the rest).** Where extraction is *not* yet feasible — `run_vcg` (HashMap + sort + SHA-256 tie-break) and all crypto — the seal (§2) pins output bytes instead. This is TESTED, not PROVEN, and that is the honest label until extraction lands.

**Aeneas supported / unsupported (so the boundary is not hand-waved):**

| Extractable today | At the frontier (parity-tested) |
|-------------------|----------------------------------|
| safe, sequential Rust; trait bounds; shared + mutable borrows; recursive fns/data; **non-nested** loops; integer arithmetic | closures; `dyn`/dynamic dispatch; `unsafe`; **nested** loops; `HashMap`/stdlib externals (need hand-written models via `-split-files`); all crypto |

So **settlement + commons are extraction-closable** (turning two TESTED rows into PROVEN-about-the-real-code), while **VCG-with-hashmap and crypto stay TESTED + MODELED** — and that boundary is a property of the tool, not a shortcut.

Integration cost is bounded: use pre-built Aeneas/Charon binaries + the sibling `aeneas-ci@v1` action, scope Charon with `--start-from`, never build OCaml (see `aeneas.yml` for the established pattern).

---

## How to update this file

When a gap lands: move the row to its true tier, cite the theorem/test name and file, and — for PROVEN rows — record the audited `#print axioms` profile. Never promote a row a tier without the artifact that earns it.
