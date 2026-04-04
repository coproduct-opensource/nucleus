# portcullis

**The only formally verified policy algebra available as a pip package.**

Lean 4 proofs. Belnap bilattice. Composable combinators.

## Install

```bash
pip install portcullis
```

## Quick Start

```python
from portcullis import (
    Verdict, CapabilityLevel, CheckResult,
    PolicyRequest, Pipeline,
    read_only, deny_disabled, deny_adversarial_taint,
    require_approval_for, deny_operations,
)

# Build a composable policy pipeline
policy = Pipeline([
    deny_disabled(),                                        # block NEVER-level ops
    deny_adversarial_taint(),                              # block prompt-injection lineage
    require_approval_for(["git_push", "create_pr"]),       # escalate dangerous ops
    read_only(),                                           # deny writes/exec by default
])

# Evaluate a request
req = PolicyRequest("read_files", CapabilityLevel.LOW_RISK)
result = policy.check(req)
assert result.is_allow()

req = PolicyRequest("run_bash", CapabilityLevel.ALWAYS)
result = policy.check(req)
assert result.is_deny()

req = PolicyRequest("git_push", CapabilityLevel.ALWAYS)
result = policy.check(req)
assert result.is_requires_approval()
print(result.reason)  # "git_push: requires human approval"

# Attach context for taint-aware checks
tainted_req = (
    PolicyRequest("web_fetch", CapabilityLevel.LOW_RISK)
    .with_context("taint", "adversarial")
)
assert policy.check(tainted_req).is_deny()
```

## The Bilattice (`Verdict`)

Four values covering all information states:

```python
from portcullis import Verdict

# Truth operations
Verdict.ALLOW.truth_meet(Verdict.DENY)   # → DENY  (AND: most restrictive)
Verdict.ALLOW.truth_join(Verdict.DENY)   # → ALLOW (OR: most permissive)
Verdict.ALLOW.negate()                   # → DENY

# Information operations
Verdict.ALLOW.info_join(Verdict.DENY)    # → CONFLICT (contradictory signals)
Verdict.UNKNOWN.info_join(Verdict.ALLOW) # → ALLOW (more info)

# De Morgan duality (proven in Lean 4)
a, b = Verdict.ALLOW, Verdict.DENY
assert a.truth_meet(b).negate() == a.negate().truth_join(b.negate())
```

| | Truth (is it permitted?) | Information (how much do we know?) |
|---|---|---|
| `truth_meet` | AND — most restrictive | |
| `truth_join` | OR — most permissive | |
| `negate` | flip Allow/Deny | |
| `info_meet` | | consensus minimum |
| `info_join` | | most informative (detects contradictions) |

## `CapabilityLevel`

Three-element lattice: `NEVER < LOW_RISK < ALWAYS`

```python
from portcullis import CapabilityLevel

CapabilityLevel.NEVER    # operation disabled
CapabilityLevel.LOW_RISK # reads, searches — low blast radius
CapabilityLevel.ALWAYS   # writes, exec, network mutations
```

## `Pipeline` — composable policy checks

Pipelines use **first-match** semantics: checks are evaluated in order and the
first decisive result (Allow, Deny, RequiresApproval) is returned.

```python
from portcullis import Pipeline

# First-match (default)
policy = Pipeline([check1, check2, check3])

# All-of: all checks must allow
policy = Pipeline.all_of([check1, check2])

# Any-of: any check may allow
policy = Pipeline.any_of([check1, check2])
```

## Built-in checks

| Constructor | Description |
|---|---|
| `read_only()` | Allow LOW_RISK ops, deny ALWAYS-level (writes/exec) |
| `deny_disabled()` | Deny ops at NEVER capability level |
| `deny_adversarial_taint()` | Deny if `taint=adversarial` in request context |
| `require_approval_for([ops])` | Escalate listed ops to RequiresApproval |
| `deny_operations([ops], reason)` | Deny listed ops with a reason |
| `deny_when_context_matches(key, val, [ops])` | Deny ops when context key=val |
| `require_min_capability(level)` | Deny ops below the minimum capability level |

## Why This Exists

AI agents need policy composition. LangChain tool calls, CrewAI agents, AutoGen tasks — they all need to answer: "is this operation allowed given these constraints?"

Most solutions use string matching or role-based checks. Portcullis provides a **mathematically complete** policy algebra:

- **4 values** (Allow, Deny, Unknown, Conflict) cover every case
- **5 operations** express any policy (proven by Bruni et al., ACM TISSEC)
- **Lean 4 proofs** verify the algebra is correct (not just tested)
- **Zero runtime overhead** — compiled Rust via PyO3
- **Composable** — build complex policies from simple, independently-testable checks

## License

MIT. Part of the [Nucleus](https://github.com/coproduct-opensource/nucleus) project.
