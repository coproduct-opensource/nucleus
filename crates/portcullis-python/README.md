# portcullis

**The only formally verified policy algebra available as a pip package.**

Lean 4 proofs. Belnap bilattice. Composable combinators.

## Install

```bash
pip install portcullis
```

## Quick Start

```python
from portcullis import Verdict

# Four values: ALLOW, DENY, UNKNOWN, CONFLICT
result = Verdict.ALLOW.truth_meet(Verdict.DENY)
assert result == Verdict.DENY  # AND: most restrictive

result = Verdict.ALLOW.truth_join(Verdict.DENY)
assert result == Verdict.ALLOW  # OR: most permissive

# Contradiction detection
combined = Verdict.ALLOW.info_join(Verdict.DENY)
assert combined == Verdict.CONFLICT  # two sources disagree

# De Morgan duality (proven in Lean 4)
a, b = Verdict.ALLOW, Verdict.DENY
assert a.truth_meet(b).negate() == a.negate().truth_join(b.negate())
```

## Why This Exists

AI agents need policy composition. LangChain tool calls, CrewAI agents, AutoGen tasks — they all need to answer: "is this operation allowed given these constraints?"

Most solutions use string matching or role-based checks. Portcullis provides a **mathematically complete** policy algebra:

- **4 values** (Allow, Deny, Unknown, Conflict) cover every case
- **5 operations** express any policy (proven by Bruni et al., ACM TISSEC)
- **Lean 4 proofs** verify the algebra is correct (not just tested)
- **Zero runtime overhead** — compiled Rust via PyO3

## The Bilattice

Two orderings on the same four values:

| | Truth (is it permitted?) | Information (how much do we know?) |
|---|---|---|
| `truth_meet` | AND — most restrictive | |
| `truth_join` | OR — most permissive | |
| `negate` | flip Allow/Deny | |
| `info_meet` | | consensus minimum |
| `info_join` | | most informative (detects contradictions) |

## License

MIT. Part of the [Nucleus](https://github.com/coproduct-opensource/nucleus) project.
