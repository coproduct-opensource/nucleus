# ADR 0008 — the public/private line

- Status: accepted (2026-09-20)
- Applies to: every manifest in this workspace, `docs/`, and any proposal to move code into
  or out of this repository
- Related: [ADR 0003](0003-gatehouse-owns-the-merge.md) draws the same kind of line for the
  merge queue; `CLAUDE.md` §"Runtime and control-plane ownership" draws it for gatehouse
  specifically. This ADR states the general rule those two are instances of.

## Context

Nucleus is MIT-licensed and public. It is developed alongside private sibling repositories
that build products on it. The boundary between them has been real for months and has never
been written down in this repository, which means it has been enforced in exactly one
direction: a private sibling runs a script that fails if one of its crates appears in
nucleus's dependency graph, and nucleus runs nothing.

The facts as of this commit:

- Nucleus declares **zero `git` dependencies and zero path dependencies that escape the
  workspace root**. The property holds today by habit.
- The private siblings consume nucleus the other way round — by pinned git rev, with the
  stated intent of moving to crates.io version dependencies — for `nucleus-oidc-core`,
  `nucleus-github-oidc`, `nucleus-fly-oidc`, `nucleus-policy-kernel`, `nucleus-policy-cert`,
  `nucleus-lineage`, `nucleus-ifc`, `nucleus-ifc-kernel`, `portcullis` and
  `portcullis-core`.
- The direction of travel has been consistent: vendor-neutral, key-free primitives migrate
  private → public and become canonical here. `nucleus-oidc-core` and the two OIDC
  validators made that trip; `docs/oidc-vendor-neutrality-audit.md` is the record of how the
  split was decided, symbol by symbol.
- The same shape is stated independently in three places already — `nucleus-control-plane`'s
  README ("`JobRunner` is a **trait** … concrete agent integrations … live in **downstream**
  crates … never here"), the vendor-side repository that carries the assistant-specific half
  of `nucleus run`, and the private isolation gate.

What is missing is the rule itself: a test a contributor can apply to a new crate without
asking, and a gate that fails if the dependency arrow ever reverses.

## Decision

**Nucleus contains everything a stranger needs to check an agent's authority, and the
mechanism that decides it. Everything required to operate a business on top of that lives
elsewhere.**

Three tests. A component belongs in this repository if and only if **all three** hold.

1. **Neutral.** No vendor, no tenant, no price list, no operator identity is baked in. A
   trait whose implementations are vendor-specific is neutral; the implementation is not.
2. **Key-free and fund-free.** It holds no production signing key, no custody, and no
   customer data. Verifying a signature is in scope. Being the signer, in production, is
   not.
3. **Checkable.** Its output is a proof, a receipt, or a decision a third party can
   recompute from declared inputs.

Two consequences are load-bearing.

**The dependency arrow is one-way, and nucleus enforces it from its own side.** A private
repository may depend on nucleus by version or by rev. Nucleus depends on nothing private —
no git dependency, no alternate registry, no path dependency escaping the repository, no
optional feature that reaches one. This is the monotonicity condition on a visibility
assignment `Vis : Crate → {public ⊑ private}`: a public crate may never depend on a private
one.

`cargo xtask visibility` decides it, over the resolved graph as `cargo metadata` reports it
*and* over every manifest the repository tracks — both halves, because neither alone is
enough. A manifest sweep cannot see a package a git-sourced dependency pulls in (`dlc-d`
declares `dlc-d-macro`, and no manifest here names it), and a root-level graph query cannot
see the thirteen satellite workspaces this repository carries. Per A-19 the gate was driven
red on the real defect — a `coproduct-private` git dependency in a satellite — before its
green was trusted.

Git dependencies are **permitted only where enumerated, one by one, in the gate.** The rule
is about privacy, and a git dependency on a public sibling does not cross the line; but it
makes the build depend on a host rather than on crates.io, and a repository that is public
today can be made private tomorrow without a line changing here. So they are listed rather
than pattern-matched, which keeps the set finite and re-verifiable. As of this ADR it is
five names across two upstreams: `dlc-core`, `dlc-crypto`, `dlc-d` and `dlc-d-macro` from
the public `coproduct-opensource/delegation_calc`, and `clippy_utils` from
`rust-lang/rust-clippy`, which the dylint passes link against and which is deliberately
never published.

**The right to check is never sold.** Verification — the receipt formats, the recompute
kernels, the offline verifiers, the proofs — stays MIT, forkable, and runnable with no
service call to us. Convenience above the proof may be sold. The proof may not be gated.
The day checking requires our permission, the guarantee this repository exists to make is
worth what our permission is worth, which is nothing a stranger can verify.

Where a component fails a test, the split is the trait seam, not a fork: the neutral half
stays here and the failing half becomes a downstream implementation. `docs/oidc-vendor-neutrality-audit.md`
is the worked example, and the general form is the one `nucleus-control-plane` already
uses.

## What this does not claim

This ADR states the rule; it does not publish the inventory. Which sibling repositories
exist, what each contains, and which side each sits on is recorded privately, because the
rule is a commitment we make and the inventory is a fact about a portfolio. A reader of
this repository needs the first to know what nucleus will and will not become; they do not
need the second.

It does not claim the line is clean today. `README.md` already documents that the reference
agent runner shipped with `nucleus run` is coupled to one assistant CLI and that
`nucleus-spec` hardcodes vendor hostnames — both fail test 1, both are known, and the
Known Gaps section is where their status lives. Neither is grandfathered by this ADR; the
rule is what they are measured against.

It does not settle licensing beyond what is already true: this repository is MIT, and
nothing here proposes a second license, a source-available tier, or a copyleft boundary.

Finally, it does not make the gate a proof of good faith. The gate decides one mechanical
question — does a manifest reach outside the public world — and a contributor who wants to
put operator-specific logic in a neutral crate can pass it easily. Tests 1 and 3 are
review's job, and naming them here is what makes "review caught it" a citation rather than
an opinion.
