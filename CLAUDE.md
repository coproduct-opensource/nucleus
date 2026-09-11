# Nucleus - Claude Code Guidelines

## Project Identity

Nucleus is an **open source, vendor-agnostic** secure execution runtime for AI agents.

**License**: MIT
**Repository**: Public (github.com/coproduct-opensource/nucleus)

## Vendor Neutrality Rules

### NEVER include in nucleus:
- Anthropic/Claude-specific code or references
- OpenAI-specific code or references
- Any LLM vendor names, SDKs, or APIs
- Vendor-specific credential formats (Claude OAuth, OpenAI API keys)
- Vendor-specific cost models or pricing

### DO include:
- Generic credential passing (`credentials.env` with arbitrary key-value pairs)
- Work-type based policies (codegen, review, research) not LLM-specific
- Generic budget models (cost per second, max USD) without vendor rates
- Standard protocols (gRPC, SPIFFE, mTLS)

### Examples

**Bad** (vendor-specific):
```rust
pub struct CredentialsSpec {
    pub claude_oauth_token: Option<String>,  // NO - vendor specific
    pub anthropic_api_key: Option<String>,   // NO - vendor specific
}
```

**Good** (vendor-agnostic):
```rust
pub struct CredentialsSpec {
    pub env: BTreeMap<String, String>,  // Generic env vars
    pub secret_ref: Option<String>,      // Reference to external secret
}
```

**Bad** (vendor-specific documentation):
```yaml
# Pass your Claude API key
credentials:
  claude_api_key: "sk-ant-..."
```

**Good** (vendor-agnostic documentation):
```yaml
# Pass credentials as environment variables
credentials:
  env:
    LLM_API_TOKEN: "your-token-here"
```

## Architecture

Nucleus provides:
1. **Isolation**: Firecracker microVMs with network/filesystem sandboxing
2. **Policy**: Permission lattice (read/write/exec/network capabilities)
3. **Identity**: SPIFFE workload identity for pods
4. **Observability**: Structured logging, audit trails

Nucleus does NOT provide:
1. LLM API integration (that's the orchestrator's job)
2. Vendor-specific credential management
3. AI-specific prompt handling

## Integration Pattern

Orchestrators handle vendor-specific concerns and translate to nucleus's generic interface:

```
Orchestrator (vendor-aware)          Nucleus (vendor-agnostic)
┌────────────────────────────┐       ┌────────────────────────────┐
│ Claude OAuth extraction    │       │ PodSpec with generic:      │
│ Anthropic rate limits      │  ──►  │   - credentials.env        │
│ Claude Code SDK            │       │   - policy profiles        │
│ Vendor cost tracking       │       │   - resource limits        │
└────────────────────────────┘       └────────────────────────────┘
```

## Testing

When writing tests, use generic placeholders:
- `LLM_API_TOKEN` not `ANTHROPIC_API_KEY`
- `test-token-123` not `sk-ant-...`
- Policy names like `codegen`, `review` not `claude_coding`

## Documentation

All documentation should:
- Use "LLM" or "AI agent" not specific vendor names
- Show generic credential examples
- Reference the orchestrator layer for vendor integration

## Mandate: gates are Rust, not shell

**New CI logic is Rust — a crate, or an `xtask` subcommand. No new shell scripts, and no
new logic added to an existing one.**

The reason is the failure record, not taste. Every trap this repository keeps rediscovering is a
shell trap that a type would have refused:

- `cmd | tail` reports **tail's** exit status, so a gate's own failure is invisible. Found in
  `check-line-ratchet.sh`, and again in `llvm-cov ... | tee` where the `--fail-under-lines`
  threshold *could never red the check*.
- `|| true` on a precondition moves the error somewhere it cannot be understood — a swallowed
  `git fetch` reported every dependent required check as SKIPPED, and GitHub counts a skipped
  required check as **passed**.
- `[ "$V" -lt N ]` with an empty `$V` errors, `if` reads that as false, and the gate **passes**.
  `GI006` in `ci-spec` exists solely to find this shape.
- A `grep` that finds nothing exits 2, which `if` also reads as false, so absence of evidence
  becomes evidence of absence — `GI002`.

Each is a category error that `Result`, a non-empty type, or an exhaustive `match` makes
unrepresentable. `ci-spec`'s `GI*` lints are a static analyser for a language we chose not to
leave; the cheaper fix is to leave it.

**Rust also gets the thing shell cannot have: tests.** `cargo xtask ci-ejections` distinguishes
`Merged | Ejected | InFlight` in an enum with three arms because measuring it by hand conflated
two of them and moved a rate across the threshold that decides a batch size. That distinction is
a type. In shell it was a bug.

### The existing 90

`git ls-files '*.sh'` is **90** files; **42** produce required gate contexts. This mandate is
forward-looking and the backlog is a migration, not a cleanup:

- **Never convert a required gate silently.** Its verdict is a required context. A conversion must
  be proved verdict-identical on the real subject — red on the real defect, green when restored —
  which is A-19's discipline and `UNCOVERED_CEILING = 0`.
- Convert when a script is being changed anyway. A gate nobody is touching is not urgent; a gate
  someone is editing is exactly when the shell tax gets paid again.
- The runner hooks (`ci/fly-runner/job-{started,completed}.sh`) are `ACTIONS_RUNNER_HOOK_*` targets
  and must be an executable on the machine, so those become a small binary baked into
  `docker/Dockerfile.runner` rather than an `xtask` subcommand — `xtask` needs a built workspace and
  these run before and after one.

### What stays shell

A single command with no branching, no arithmetic, and no exit-code inspection. The moment there
is an `if`, a count, or a pipeline whose status matters, it is Rust.

## Mandate: make the defect unwritable

**`docs/adr/0007-make-the-defect-unwritable.md` is thirty-nine rules, each derived from a defect
this repository shipped and fixed. New Rust follows them; existing Rust follows them as each file
is touched. Cite the rule id (`C-4`, `E-1`, …) in review.**

They came out of a full read of both repositories' history: 252 defect records, of which **58 —
23% — needed no language extension, no verifier and no rewrite.** The type discipline already
existed in stable Rust and was not applied.

The one to know by heart is **C-4**, because it is the reason the ADR exists. In `f7f9719b`,
`DischargedBundle` was already `!Clone`, `!Copy` and `#[must_use]` — every affine signal Rust
offers was present — and a one-shot authorization could still be replayed, because three
signatures took it by `&`. Nothing was missing from the language. The refactor was the fix, and a
written rule would have been cheaper.

The nine families, in one line each:

- **A — sum types that lost a case.** "Could not look" is never "looked and it was fine"; a `bool`
  may not carry a three-valued decision; no blanket `map_err`.
- **B — defaults that grant.** No `#[derive(Default)]` on a security type; `Option::None` may not
  mean unrestricted; a `_ =>` arm denies.
- **C — evidence and witnesses.** Evidence has a private constructor and is minted by the checker;
  a capability is indexed by what it authorizes; a one-shot right is taken **by value**.
- **D — order as a type.** Typestate, not source-line adjacency. A `compile_fail` doctest is not a
  substitute for a type.
- **E — records and exhaustiveness.** No `..` on a policy path — `E0027` is the mechanism.
- **F — derive, never restate.** Derived serialization; one `Deserialize` struct and a `for` loop;
  never a count restated beside the thing it counts.
- **G — one decider per fact.** If a fact is written twice, delete one. A parity test leaves two
  copies and converts the next drift into a test failure rather than an impossibility.
- **H — ambient authority.** No `set_var`; an effect is reachable only from a witness.
- **I — gates that can fail.** Every gate driven red on the real defect first (A-19).

Three enforcement tiers — `clippy.toml`, a `tools/nucleus-*-lint/` dylint pass, or review — and
the tier is named on every rule so "review" reads as a gap rather than as coverage. **A-19 binds
the lints too: a lint ships only once it has been driven red on the commit its rule cites.**

What the ADR does **not** claim: 58 of 252 is not a majority, these rules reach no effectful
defect directly (103 records are in code that spawns, syscalls or awaits), and none of them
addresses `unsafe`. Those limits are in the ADR rather than left to be discovered.

## Startup Loops

On init, read `LOOPS.md` (git-ignored, local only) and start any loops defined there.
