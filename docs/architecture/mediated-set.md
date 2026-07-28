# The Mediated Set

Which code is inside the complete-mediation guarantee, which is outside, and why.

This page exists because the guarantee is **relative to a boundary**. "Every effect is
mediated" is meaningless until "which effects" is pinned down, and the Lean mediation
theorem's premise — *every effect entry point consumes a scoped `Authority`* — is only
discharged over the crates the `mediated` lint actually runs on. A set that is
described but not enforced is a claim, not a boundary.

## The set

| In the set | Why |
|---|---|
| `portcullis-effects` | The effect traits. All 13 methods take an `Authority` by value. |
| `nucleus` (`Sandbox`, `Executor`) | The other filesystem and process path. All 22 `DecisionToken`-taking `Sandbox` methods take an `Authority`; the `Executor` threads one to the spawn. |
| `portcullis-core::capability_traits` | The typed-context surface. Reachable from `NucleusRuntime::with_typed_context`, so it is agent-facing. |

Everything else is outside, and the guarantee says nothing about it.

## What "agent-attributed" means

The distinction is not "does it touch the disk" but **on whose authority**. An effect
performed *because an agent asked for it* is in the set. An effect the runtime performs
to do its own job — spawn a jailer, serve HTTP, append to its own audit log, read its
own config at startup — is not, because there is no agent authority to discharge
against and no obligation that could meaningfully be checked.

Conflating the two would be worse than leaving them separate: it would mean minting
authorities for the runtime's own bookkeeping, which devalues the token.

## Excluded, with reasons

Run over the whole set, `mediated` reports 21 functions. Three were closed (below);
the rest are excluded deliberately:

| Excluded | Category | Reason |
|---|---|---|
| six `*::load_from_dir` loaders (`ComposeWorkflow`, `Compartmentfile`, `EnterpriseAllowlist`, `ManagedSettings`, `PolicyRuleSet`, `ParserRegistry`) | Config loading | Runtime startup, before any agent exists. There is no session to discharge against. |
| `sink::JsonlSink::{open, iter}`, `merkle::MerkleSink::*`, `merkle::read_checkpoints`, `audit_backend::FileAuditBackend::{append, count, load_all}` | Audit / lineage writing | The runtime recording what happened. |
| `file_signer::Pkcs8FileSigner::from_pkcs8_pem_file` | Key loading | Startup, operator-supplied material. |
| `Sandbox::new`, `PodRuntime::{new, with_approver}` | Construction | Creating the sandbox root before any agent holds it. |
| `Sandbox::{exists, exists_approved}` | **Signature-blocked, not judged safe** | These return `bool` with no error channel, so requiring an authority is a signature change rather than a check. Genuinely in the set by rights: `exists` is an information-disclosure probe. Tracked, not excused. |
| `nucleus`/`nucleus-tool-proxy` infrastructure | Jailer spawn, HTTP serving | The runtime's own process and network use. |

**The audit-sink exclusion is the one that deserves scrutiny**, because it is the case
where "outside the set" is not obviously benign: an unmediated write path exists, and
it writes attacker-influenced content (the subject of a denied action). Two things
bound it. The destination is fixed at construction and not agent-controlled. And
requiring an agent authority to write the audit log would let a *denied* agent suppress
its own denial record — the cure would be worse. That is a weaker argument than the
others on this page, and it is stated as such rather than buried.

## Closed rather than excluded

`portcullis_core::capability_traits::{read_file, write_file}` performed real
`std::fs` calls behind only a phantom-type capability check — no obligation discharge,
no `FlowTracker` update, no path allowlist — and were reachable from
`NucleusRuntime::with_typed_context`, whose own doctest demonstrated reading a file
that way.

Six of the eight operations in that module were already stubs returning "use the
mediated path". These two silently were not. They are now stubs matching their
siblings, which is the fail-closed direction: the typed context demonstrates
*compile-time capability checking* and is not an effect path.

They had no production callers.

`Sandbox::read_to_string_for_search` — the grep/search read path — took no
`DecisionToken` and carried a comment saying the caller *"must have already obtained a
GrepSearch decision"*. A convention where an enforcement belongs, and agent-reachable.
It now requires an `Authority` scoped to `(GrepSearch, AuditLogAppend)`.

That one has a cost worth naming: the search loop mints **one discharge per file**, so
a grep over N files runs N preflights. That is the affine model working as designed —
an `Authority` buys one read — and the alternative, one authority covering a whole
directory walk, is exactly the replay the by-value cutover removed. If the cost ever
matters, the answer is a coarser sink class, not a reusable token.

## Enforcement

The boundary is enforced by CI, not by this page:

```sh
cargo dylint --lib nucleus_mediation_lint -- \
  -p portcullis-effects -p portcullis-core -p nucleus
```

Adding a crate to the set means adding it to that invocation. Removing one means
editing this page and saying why.

**Soundness is relative to running over the whole set.** `mediated` analyses one crate
at a time and relies on cross-crate callees being covered by their own pass; linting
part of the set silently weakens the guarantee rather than failing loudly. See
`tools/nucleus-mediation-lint/README.md`.
