# Verified Claims

Machine-checked properties of the Nucleus security kernel. Each claim links to
its proof, states what it guarantees and what it does not, and names the CI gate
that enforces it on every pull request.

**Verification stack:**
- **Lean 4** kernel-checked proofs via Aeneas extraction (types + theorems)
- **Kani BMC** bounded model checking of Rust implementations (159 harnesses)
- **Rust type system** structural enforcement via sealed types and phantom tags

---

## Tier 1: Algebraic Properties (Lean 4 + Kani BMC)

### 1. IFC label join is a semilattice

**Plain English:** When two data sources are combined (e.g., a user prompt mixed
with web content), the resulting security label is always at least as restrictive
as the most restrictive input. Combining data never makes it *less* restricted.

**Formal statement:** `(IFCLabel, join)` is a commutative, associative,
idempotent semilattice with `bottom` as identity.

**Proved in:**
- Lean 4: [`lean/IFCSemilatticeProofs.lean`](../crates/portcullis-core/lean/IFCSemilatticeProofs.lean) — `ifc_join_idempotent`, `ifc_join_comm`, `ifc_join_assoc`
- Kani: `proof_ifc_join_idempotent`, `proof_ifc_join_commutative`, `proof_ifc_join_associative` (portcullis-core)

**What it does NOT prove:** That labels are assigned correctly at runtime.
The algebra is sound; labeling depends on correct integration.

**CI gate:** Lean proofs run in the `Aeneas (Rust -> Lean 4)` CI job. Kani
harnesses run in the `Mutation Testing` job. Both block merge on failure.

---

### 2. Taint is monotone (no silent cleansing)

**Plain English:** Once an AI agent has processed adversarial content (e.g., a
web page with a prompt injection attempt), that contamination is permanently
recorded on every output derived from it. No sequence of operations can wash it
out without explicit human authorization.

**Formal statement:** For all derivation classes `x`:
`join(x, Deterministic) = x` and `join(OpaqueExternal, x) = OpaqueExternal`.
The session taint ceiling is monotonically non-decreasing.

**Proved in:**
- Lean 4: [`lean/DerivationProofs.lean`](../crates/portcullis-core/lean/DerivationProofs.lean) — `no_silent_cleansing`, `join_monotone_left`, `join_opaque_left`
- Kani: `proof_derivation_no_silent_cleansing`, `proof_derivation_join_monotone` (portcullis-core)
- Runtime: `FlowTracker::session_taint_ceiling` is only raised, never lowered (except via explicit `reset_session_ceiling` which requires human authority)

**What it does NOT prove:** That the agent will not be compromised. That prompt
injection will not succeed. Only that if it does, the taint is tracked and
cannot be erased silently.

**CI gate:** Lean + Kani in CI. The `reset_session_ceiling` escape hatch is
audited as a security-sensitive operation (#1233).

---

### 3. Adversarial integrity is absorbing

**Plain English:** Mixing any data with adversarial-integrity content always
produces adversarial-integrity output. There is no "dilution" — even one drop
of adversarial input contaminates the entire result.

**Formal statement:** For all `IntegLevel b`:
`Adversarial meet b = Adversarial`.

**Proved in:**
- Lean 4: [`lean/IFCSemilatticeProofs.lean`](../crates/portcullis-core/lean/IFCSemilatticeProofs.lean) — `integ_inf_adversarial_left`, `integ_inf_adversarial_right`
- Lean 4: `invariant_exploit_propagates_taint` (end-to-end IFC scenario)

**What it does NOT prove:** That adversarial content will be detected. Only that
once labeled, the label cannot be weakened through data combination.

**CI gate:** Lean `Aeneas` job.

---

### 4. Secret confidentiality is absorbing

**Plain English:** Mixing any data with secret-classified content always
produces secret-classified output. Combining a secret API key with public
documentation does not make the result "mostly public."

**Formal statement:** For all `ConfLevel b`:
`Secret sup b = Secret`.

**Proved in:**
- Lean 4: [`lean/IFCSemilatticeProofs.lean`](../crates/portcullis-core/lean/IFCSemilatticeProofs.lean) — `conf_sup_secret_left`, `conf_sup_secret_right`

**What it does NOT prove:** That secrets are labeled correctly at source. A
secret not labeled as `Secret` will not benefit from this guarantee.

**CI gate:** Lean `Aeneas` job.

---

### 5. Capability lattice is a distributive Heyting algebra

**Plain English:** The permission system (which tools an agent can use) follows
the mathematical rules of a Heyting algebra. This means permissions compose
predictably: restricting permissions always produces a valid, less-permissive
result; combining permissions always produces a valid, more-permissive result.

**Formal statement:** `(CapabilityLattice, meet, join, implies)` satisfies all
Heyting algebra axioms, including the adjunction property `a meet b <= c iff
a <= b implies c`.

**Proved in:**
- Kani: `proof_r1_heyting_adjunction`, `proof_r4_lattice_heyting_adjunction` (portcullis)
- Lean 4: [`lean/generated/PortcullisCore/Types.lean`](../crates/portcullis-core/lean/generated/PortcullisCore/Types.lean) — type generation from Aeneas

**What it does NOT prove:** That the 13 capability dimensions are the right
ones for your use case. The algebra is generic; the dimensions are
application-specific.

**CI gate:** Kani in `Mutation Testing` job. Lean type generation in `Aeneas` job.

---

## Tier 2: Structural Safety (Rust Type System)

### 6. Obligation bypass is a type error

**Plain English:** There is no way to execute a side effect (file write, web
fetch, shell command) through `NucleusRuntime` without first passing the
obligation discharge check. The `DischargedBundle` required by effect functions
can only be obtained from a successful `preflight_action()` call — its
constructor is private.

**Structural enforcement:** `DischargedBundle` contains a private `Seal` field
that cannot be named outside its module. `Discharged<O>` tokens are zero-sized
proof witnesses; `Discharged::mint()` is `fn` (not `pub fn`).

**Proved in:** Compile-fail doc-test on `DischargedBundle` (portcullis-core/src/discharge.rs)

**What it does NOT prove:** That the obligation checks themselves are correct.
Only that they cannot be skipped. The checks' correctness is tested by 33 unit
tests and the Kani harnesses above.

**CI gate:** `Tests` job runs the compile-fail doc-test. A PR that makes the
`Seal` field public or adds a public constructor would fail the doc-test.

---

### 7. Confidentiality downflow is enforced

**Plain English:** Data classified as `Secret` cannot flow to a sink classified
as `Public` or `Internal` through `NucleusRuntime`. The session-level
confidentiality ceiling prevents laundering through clean intermediaries: if
the session has ever observed `Secret` data, writing to any non-`Secret` sink
is blocked.

**Structural enforcement:**
- `FlowTracker::session_conf_ceiling` is monotonically non-decreasing
- `check_exfiltration_safety()` checks both node-level and session-level conf
- At the type level, `Labeled<T, I, Secret>` does not implement
  `ConfAtMost<Public>`, so passing secret data to a public-gated function is a
  compile error

**Proved in:** 21 unit tests in `ifc_api::tests` + compile-fail doc-test on `Labeled`

**What it does NOT prove:** That all data sources are labeled with the correct
confidentiality. Mislabeled data bypasses the check. Source labeling is the
integrator's responsibility.

**CI gate:** `Tests` job.

---

### 8. Type-level IFC prevents tainted-to-trusted flow

**Plain English:** A function that requires `Trusted`-integrity input will not
compile if passed `Adversarial`-integrity data. This catches the most common
IFC violation — using web-scraped content in a privileged operation — at
compile time rather than at runtime.

**Structural enforcement:** `Labeled<T, Adversarial, C>` does not implement
`IntegAtLeast<Trusted>`. The only way to promote `Adversarial` to `Untrusted`
is `promote_integrity()` which requires an explicit `DeclassifyReason`. The
only way to promote `Untrusted` to `Trusted` is `promote_to_trusted()` which
accepts only `HumanReview` or `DeterministicVerification` — `Sanitization`
alone is rejected.

**Proved in:** Compile-fail doc-test on `Labeled` + 22 unit tests in `labeled::tests`

**What it does NOT prove:** That runtime IFC checks are redundant. The type-level
system is an approximation — dynamic data flow through the `FlowTracker` remains
necessary for paths where the type is erased.

**CI gate:** `Tests` job.

---

## What happens when a proof breaks

1. The `Aeneas (Rust -> Lean 4)` or `Mutation Testing` CI job fails
2. The merge queue rejects the PR
3. The PR author sees the specific theorem that failed and the Lean/Kani error
4. The Constitutional Gate (external webhook) logs the failure for audit

No code that breaks a verified claim can reach `main`.

---

## Known Gaps

The claims above hold for code paths that go through `PolicyEnforced` or
`NucleusRuntime`. The following gaps mean they do not hold universally:

### Enforcement completeness ([#1216](https://github.com/coproduct-opensource/nucleus/issues/1216))

146 call sites in `nucleus-claude-hook` and `nucleus-mcp` call `std::fs`,
`std::process::Command`, and `reqwest` directly, bypassing the `PolicyEnforced`
effect layer. The effect layer exists and is verified, but is not structurally
required at every I/O site. Migration is tracked in #1216.

**Impact:** An operation routed through these 146 call sites gets capability
checking via `Kernel::decide_term()` (which runs obligation discharge), but does
NOT get the `PolicyEnforced` effect wrapper. A bug in the call site code could
perform I/O without any policy gate.

### NucleusRuntime escape hatch ([#1248](https://github.com/coproduct-opensource/nucleus/issues/1248))

`NucleusRuntime::effects()` returns a raw `PolicyEnforced` bundle that checks
capabilities but does NOT run obligation discharge or update the FlowTracker.
The mediated methods (`read_file`, `write_file`, etc.) compose all three layers.
A developer who discovers `.effects()` first uses the weaker path.

### Type-level IFC not composed into runtime ([#1249](https://github.com/coproduct-opensource/nucleus/issues/1249))

`NucleusRuntime::read_file()` returns `Vec<u8>`, not `Labeled<Vec<u8>, Trusted,
Internal>`. The compile-time IFC layer (`Labeled<T, I, C>`) and the runtime IFC
layer (`FlowTracker`) are independently correct but not composed at the API
boundary. Agents using `NucleusRuntime` get runtime tracking but not compile-time
enforcement of IFC constraints.

---

## Verification coverage summary

| Layer | Tool | Harnesses | Scope |
|---|---|---|---|
| IFC semilattice | Lean 4 | 19 theorems | Label algebra, join/meet laws, absorption |
| Derivation monotonicity | Lean 4 | 9 theorems | Taint propagation, no-cleansing |
| Capability Heyting algebra | Kani BMC | 26 harnesses | Meet/join/implies, adjunction |
| Kernel invariants | Kani BMC | 133 harnesses | Exposure, delegation, guards, flow |
| Discharge sealing | Rust types | 1 compile-fail test | No forging of `DischargedBundle` |
| Type-level IFC | Rust types | 1 compile-fail test | No `Adversarial` -> `Trusted` flow |
| Confidentiality downflow | Unit tests | 21 tests | No `Secret` -> `Public` flow |
