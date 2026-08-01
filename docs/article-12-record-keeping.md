# Article 12 record-keeping

EU AI Act Article 12 requires high-risk AI systems to record events automatically
over their lifetime, in a form that supports traceability. It applies from
**August 2026**. This page states exactly what nucleus does, what the artifact
proves, and what it does not.

Article 12 sits in the Tier 2 penalty band — up to **€15 000 000 or 3 %** of
worldwide annual turnover, whichever is higher. It is not the 7 % band, which
applies to the Article 5 prohibitions.

## What is recorded

With `--art12-log <path>` (or `NUCLEUS_TOOL_PROXY_ART12_LOG`), the tool proxy
appends one hash-chained, HMAC-signed record per kernel decision — **allows,
refusals and deferrals alike**.

Recording refusals is the point. Every caller reaches the kernel through `?`, so
a refusal returns before any later step runs; an evidence log wired at a call
site would contain only allows. It would be non-empty, plausible, and wrong in
the most dangerous possible direction. The record is emitted by a `VerdictSink`
in the chain, built by the one constructor callers can reach, so there is no path
around it.

Each record carries the operation and subject, the verdict and its machine-stable
deny code, the gate class, the permission-lattice checksum, the actor, the
verified-admission state, and the causal DAG's independent opinion of the same
decision (`flow_cross_check`). Every one of those fields is folded into the
signed preimage.

## What happens when recording fails

The log latches **degraded** on a write failure and counts what it dropped. The
next operation is then refused before it executes.

That is deliberate. A record-keeping log that keeps running after it stops
recording leaves a gap that is invisible in the artifact — the file simply has
fewer lines than the session had decisions, and nothing says so. Bounding the
loss to the records already lost is worth refusing traffic for.

The latch is read at preflight, not at record: a call whose effect already
happened is not retroactively failed into a duplicating retry.

## Where the log must not live

**Not inside the agent's workspace.** Startup refuses such a path rather than
warning.

This is not hypothetical caution. `.nucleus-exit-report.json` was written into
`work_dir` and the agent's own path lattice permitted reading it, so a session
could read the runtime's assessment of itself — including which mediation
invariants it had tripped. The Article 12 log is a strictly richer record of the
same kind. Nothing about a session's surveillance record belongs in that
session's readable surface.

## Verifying a log

```
nucleus-audit verify-art12 --log /path/to/art12.jsonl --secret <secret>
```

The verifier reconstructs each record's canonical preimage **from the record's
own fields** — not by re-serialising, because JSON key order and escaping are not
stable across serde versions and a verifier that re-serialises is checking its own
serialiser. It checks sequence continuity, hash chaining, and the HMAC.

`--json` emits a machine-readable report: record count, chain head, time span,
how many records identify an authenticated actor, and the verdict distribution.

## What verification proves — and what it does not

The verifier prints this, and carries it as data in the JSON report, so a
consumer cannot render "verified" without it.

| Established | Not established |
|---|---|
| The records present are consecutive and unaltered | That the log is **complete** — a chain cannot show the process recorded every decision it made |
| No party **lacking the signing secret** modified the file | That a **holder** of the secret did not rewrite history |
| Each record's fields match its own hash and signature | That the signer is independent of the signed |

The third row is the one to read twice. If the pod derived its own signing
secret — no operator-supplied `--audit-secret` — then the pod can re-sign any
history it likes, and **the log alone is not evidence against the pod**.

## The executor attestation closes that

At pod exit the tool proxy reports its final chain head in the exit report, and
`nucleus-node` signs `(session_id, chain_head, records, dropped, executor_id)`
with its **executor key** — Ed25519, resident on the node, role-separated from
the task-issuer key, and never seen by the pod. The attestation travels with the
receipt in the `session-complete` body, and the chain head is committed into
`v1_content_hash` so it cannot be stripped in flight.

```
nucleus-audit verify-art12 --log art12.jsonl --secret <s> \
    --attestation att.json --executor-pubkey <hex>
```

The verifier checks the signature over the attestation's own preimage **and**
that the head it names is the head recomputed from the log. Both halves are
required: a valid signature over a different head proves only that some other log
was attested. When both pass, the secret-holder limitation is lifted from the
report — that is the one case where it does not apply.

The signer and the verifier share one preimage function in
`portcullis::art12_record`, for the reason `Art12Record` lives there too: two
renderings that agree today break the first time either side gains a field, and
they break by *rejecting authentic evidence*.

Two limits remain, both structural:

- **It binds the head, not the content.** A pod that recorded nothing exports a
  validly signed empty log. Completeness stays unverifiable from the artifact.
- **It binds a moment.** Signing happens at pod exit, after the host has stopped
  the pod, so the head is one the pod can no longer move. A signature taken while
  the pod still ran would bind a head the pod could advance past.

An absent attestation means no Article 12 log was kept: `attest_art12` returns
`None` rather than signing an empty head, because a signature over nothing would
assert record-keeping that did not happen.

## Current limits

- **Opt-in.** Without `--art12-log`, no Article 12 record is kept. Nothing in the
  runtime claims record-keeping happens without it, but "compliant by default" is
  not the current state.
- **Retention is the operator's.** Article 12 expects retention appropriate to
  purpose (at least six months for certain obligations under Article 19). Nucleus
  writes an append-only file; rotation, retention and off-host durability are
  deployment concerns it does not manage.
- **Identification of persons** is only as good as the actor the caller
  authenticated as. The verifier reports how many records name an authenticated
  actor precisely so a log of anonymous decisions is visible rather than passing
  as a green tick.
