# Add a Policy Check in 10 Lines

The fastest way into nucleus security policy is implementing a single trait and plugging into the combinator API. No lattice theory required at level 0.

## Level 0 — Custom check in 10 lines

```rust
use portcullis_core::combinators::{PolicyCheck, PolicyRequest, CheckResult};

struct MaxFileSize { limit_kb: u64 }

impl PolicyCheck for MaxFileSize {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        let size = req.context.get("file_size_kb")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        if size > self.limit_kb {
            CheckResult::Deny(format!("file too large: {size}KB > {}KB", self.limit_kb))
        } else {
            CheckResult::Allow
        }
    }
    fn name(&self) -> &str { "MaxFileSize" }
}
```

That's it. `PolicyCheck` has two methods. Both required.

## Level 1 — Compose with built-ins

```rust
use portcullis_core::combinators::all_of;
use portcullis_core::builtin_checks::*;

let policy = all_of(vec![
    Box::new(ReadOnly),
    Box::new(RequireApprovalFor::new(["git_push", "create_pr"])),
    Box::new(no_web_during_code_review()),
    Box::new(MaxFileSize { limit_kb: 1024 }),
]);

let req = PolicyRequest::new("read_files", CapabilityLevel::LowRisk);
match policy.check(&req) {
    CheckResult::Allow => { /* proceed */ }
    CheckResult::Deny(reason) => eprintln!("denied: {reason}"),
    CheckResult::RequiresApproval(reason) => { /* ask human */ }
    CheckResult::Abstain => { /* no opinion — apply default */ }
}
```

### Combinators

| Combinator    | Semantics                                          |
|---------------|----------------------------------------------------|
| `all_of`      | All must allow — first deny wins (AND)             |
| `any_of`      | Any may allow — first allow wins (OR)              |
| `first_match` | Try in order, return first decisive result         |
| `Not`         | Flip Allow ↔ Deny, leave RequiresApproval/Abstain  |

## Level 2 — Bilattice verdicts

The combinator `CheckResult` maps to a four-valued `Verdict`:

```
Allow   → permitted
Deny    → forbidden
Unknown → needs human input (RequiresApproval + Abstain)
Conflict → two sources disagree (= Quarantined in nucleus)
```

Use bilattice operations to merge verdicts from independent sources:

```rust
use portcullis_core::bilattice::Verdict;

// AND: both must allow
let v = Verdict::Allow.truth_meet(Verdict::Deny); // → Deny

// OR: either may allow
let v = Verdict::Deny.truth_join(Verdict::Allow);  // → Allow

// Contradiction detection: two sources disagree
let v = Verdict::Allow.info_join(Verdict::Deny);   // → Conflict
```

`Conflict` maps to quarantine in nucleus — the operation is blocked and the
incident logged for human review.

## Level 3 — Formal proofs (optional)

The five bilattice operations (`truth_meet`, `truth_join`, `negate`,
`info_meet`, `info_join`) are **functionally complete** — any policy expressible
in this algebra can be built from these five (Bruni et al., ACM TISSEC).

The Lean 4 proofs in `lean/` verify that `Verdict` forms a Belnap bilattice
with correct HeytingAlgebra structure. The Rust type is machine-translated via
Aeneas — the proof target IS the production type.

## Built-in checks reference

| Check | Context keys | Behaviour |
|-------|-------------|-----------|
| `ReadOnly` | — | Deny when `required_level == Always` |
| `DenyDisabled` | — | Deny when `required_level == Never` |
| `RequireMinCapability(level)` | — | Deny when level not implied |
| `RequireApprovalFor(ops)` | — | RequiresApproval for listed operations |
| `DenyOperations(ops, reason)` | — | Deny listed operations |
| `DenyWhenContextMatches(k,v,ops)` | any | Deny ops when context[k]==v |
| `DenyAdversarialTaint` | `taint` | Deny when `taint=adversarial` |
| `RequireTrustedSource` | `source_trust` | Deny when `source_trust=untrusted` |
| `BudgetGate(max_µusd)` | — | Deny when cumulative spend ≥ limit |
| `RateLimit(max_calls)` | — | Deny after N calls |
| `no_web_during_code_review()` | `mode` | Deny web ops when `mode=code_review` |
| `approval_for_git_push()` | — | RequiresApproval for git_push/create_pr |

## Next steps

- Run the working example: `cargo run --example custom_policy`
- Python API: `pip install portcullis` (PyO3 bindings, same algebra)
- Formal proofs: `lean/portcullis/Bilattice.lean`
- IFC integration: `portcullis_core::ifc_api` for taint-based policies
