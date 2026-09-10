# Writing an effect pack

An effect is the unit of authority a **person** reads. `github/read-ci-logs`,
`kubernetes/apply-manifest`, `database/run-migration` — each is a sentence about
work, lowered to a sentence about capabilities that nobody has to read.

Packs are data: TOML under `crates/portcullis/effects/` for the built-in ones,
and `.nucleus/effects/` for a repository's own. Adding one widens the basis of
what can be delegated ([ADR 0005](adr/0005-delegatable-agency.md), decision 5) —
which is why pack quality is a security property and not a convenience.

## A pack cannot widen authority

This is the property that makes packs safe to accept from anywhere, and it is
worth being precise about *why* rather than asserting it.

An effect **lowers** to a set of capabilities, and lowering starts every
dimension at `Never` and raises only what the effect lists
(`EffectCatalog::lower`). The result is then **met with the ceiling profile**
before it becomes a grant, using the same `delegate_to` a certificate mint uses.
So a pack can:

- ask for less than the ceiling — the grant is narrower;
- ask for more than the ceiling — the meet clips it, and the clipped effect
  appears in the grant's `cannot` list *with the reason*;
- ask for something incoherent — the goal starves, and `--goal` fails with a
  message naming the remedy rather than falling back to a permissive profile.

What it cannot do is produce a lattice above the ceiling. Widening happens in
exactly one place, `POST /v1/escalate`, and that is not the pack's to call.

## The shape

```toml
[plugin]
name = "kubernetes"          # matches the filename; the first half of every id
version = 1

[[effect]]
id = "read-logs"             # `kubernetes/read-logs` is what a person sees
title = "Read pod logs"      # the line in the Can / Cannot list
risk = "read"                # read | write_local | execute | publish | mutate_remote | destructive

[effect.lowers]              # what it becomes
operations = ["run_bash"]    # core dimensions raised above Never
sinks = ["bash_exec"]        # sink classes it writes to
hosts = ["logs.*.amazonaws.com"]   # egress it needs (omit if none)

[effect.matches]             # how a request is recognised as this effect
mcp_tools = ["k8s_logs"]     # exact MCP tool names
commands = ["kubectl logs"]  # command prefixes
http = [{ method = "GET", host = "slack.com", path = "/api/*" }]
```

### `matches` is the part that decides what a grant means

`lowers` says what an effect *costs*. `matches` says what it *covers*, and it is
where packs go wrong. Three rules, each learned from a bug:

**1. An effect with no `http` shape but a `hosts` list vouches for its hosts.**
That is deliberate — a host-level effect like `git/push-branch` needs it — but it
means a broad host list is a broad grant. The first draft of the AWS pack gave
`read-inventory` `hosts = ["*.amazonaws.com"]` and no shape, so a grant of "list
cloud resources" admitted a `POST` to `iam.amazonaws.com`: the one call that can
rewrite the boundary itself. The pack's own conformance test caught it. Name
service hosts one by one, or add a shape that discriminates.

**2. Write a shape only where it discriminates.** A shape that covers everything
its neighbours cover is worse than no shape, because it looks like precision. The
AWS JSON-protocol services all `POST /` and select by an `X-Amz-Target` header
the index does not carry — so those effects carry no `http` entry, and say so in
a comment, rather than a `POST *.amazonaws.com /*` that would vouch for the whole
account.

**3. Two effects of different risk must not share a tool name.** A grant of the
lower one would silently admit the higher one's work. There is a test for it
(`no_tool_name_is_claimed_by_two_effects_of_different_risk`).

### Host patterns

A pattern is dot-separated labels; a label may be `*`, which matches **one or
more whole labels**. `*.amazonaws.com`, `logs.*.amazonaws.com`, `api.github.com`.
A `*` is a whole label or it is not a wildcard: `*foo.example` is rejected, so no
pattern matches a fragment of a name. Matching is anchored at both ends, so
`*.amazonaws.com` admits neither `evil-amazonaws.com` nor
`amazonaws.com.evil.example`, and a `*` never matches zero labels.

## Every pack ships an admits/denies table

A pack is a claim about what a grant means, and a claim with no counterexample
beside it is a claim nobody checked. Each pack states, as a test, a request it
admits **and** a request it does not — where the denial names the effect that
*would* have admitted it, because that name is what an escalation proposal is
built from.

```rust
#[test]
fn aws_object_reads_do_not_carry_object_writes() {
    let catalog = EffectCatalog::builtin().unwrap();
    let g = granted(&["aws/read-object"]);
    admits(&catalog, &g, "GET", "bucket.s3.amazonaws.com", "/q3.csv", "aws/read-object");
    refuses(&catalog, &g, "PUT", "bucket.s3.amazonaws.com", "/q3.csv", "aws/write-object");
}
```

Two whole-catalog tests keep those rows from passing for the wrong reason:
`no_builtin_effect_is_unrecognisable` (an effect with an empty `matches` index
grants nothing and denies nothing, so every "refuses" beside it would pass
vacuously) and the shared-tool-name test above.

## Compiler rules propose reads, not mutations

A rule maps goal phrases to effects (`crates/nucleus-task-compiler/src/rules.rs`).
The rules for surfaces beyond the repository — cloud, cluster, database, chat —
propose **read effects only**, and the asymmetry is the design: a goal is
evidence about what a person wants to learn, and much weaker evidence about what
they will let be changed. "the deploy is broken" plausibly means read the logs;
it does not mean roll something out.

Mutating effects stay reachable by being *asked* for — `--effects
kubernetes/apply-manifest`, or the escalation proposal the read-only grant's
denial produces. Both put the decision in front of a person, which is where a
deploy belongs. `no_goal_phrase_proposes_a_mutation_beyond_the_repository` pins
it, and a companion test checks those same goals do fire their rules, so the
absence is a decision rather than a failure to match.

## Checklist

- [ ] One id per unit of work a person would grant or withhold *separately*.
- [ ] `title` reads as a sentence about work, not about an API.
- [ ] `risk` graded so the destructive ones sit above the shipped ceilings.
- [ ] `hosts` names services, not whole providers.
- [ ] `http` shapes only where they discriminate; a comment where they cannot.
- [ ] No tool name shared across risk grades.
- [ ] An admits/denies test per pack, the denial naming the effect that would admit.
- [ ] Compiler rules, if any, propose reads only.
