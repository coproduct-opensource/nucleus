# ADR 0003 — gatehouse owns the merge

- Status: accepted (2026-09-06)
- Supersedes the merge-queue half of [ADR 0002](0002-ci-is-a-verified-system.md); everything
  else in 0002 stands
- Applies to: `ci/merge-queue.toml`, `ci/required-checks.txt`, `crates/ci-spec/**`, branch
  protection on `main`, the merge-queue ruleset

## Context

ADR 0002 made the merge queue a modelled system: the constants that govern it are pinned in
`ci/merge-queue.toml`, the capacity theorem reasons about those constants, and
`cargo xtask ci-spec live-parity` reds when the pins and GitHub's settings drift. What it did
not change is the thing underneath: a verdict is a row in GitHub's database saying that some
runner reported success on some commit. Nothing about that row can be checked afterwards, so
the queue re-runs every gate on every group — which is why the pool saturates.

gatehouse replaces the verdict, not the runner. A gate declares its inputs, its environment,
its capabilities and its command; running it mints a receipt signed inside the sandbox and
appended to a transparency log; the queue verifies receipts and runs only what it has no
receipt for. The receipt is checkable by anyone with the verifier and the log — the property
GitHub's row does not have.

## Decision

**gatehouse's queue merges `main`.** GitHub's merge queue is switched off, and the single
required context `gatehouse/required` carries the roll-up of every Required gate at the tree
under review. The other contexts stay on their workflows and stay required; they move to
gatehouse gate by gate, each after its cold wall time is measured, and never before.

Three consequences are load-bearing, and each is checked:

1. **`ci/merge-queue.toml` names an owner.** `owner = "github"` means a ruleset carries the
   `merge_queue` rule that enforces the queue; `owner = "gatehouse"` means no active ruleset
   may carry one. `live-parity` decides this in both directions: GitHub's queue still running
   under a gatehouse pin is two queues merging one branch, and no queue at all under a GitHub
   pin means nothing builds a group. With a gatehouse pin the check is over *every* ruleset,
   not the pinned id, because a queue re-enabled under a new ruleset is exactly the drift that
   would otherwise go unseen.

2. **`strict` is true.** Under GitHub's queue, requiring a branch to be up to date before
   merging forced a rebase before every merge and was half of the fifteen-hour stall of
   2026-09-04. Under gatehouse's it is the opposite: it is what makes the tree a receipt was
   verified at the tree that actually gets merged, without building speculative merge trees
   for a queue one entry deep. The pin and the setting move together, and `live-parity`
   catches either moving alone.

3. **The merge is asserted after the fact.** gatehouse merges through the API and then reads
   the merged commit back by content: if `tree(main)` is not the tree its receipts were
   verified at, the queue pauses and a human resumes it. A merge nobody verified is a stop,
   not a warning.

## What this does not claim

The capacity theorem (`ci/lean/CiSpec/Capacity.lean`) is about a queue with build concurrency
one and no competing runs. gatehouse's queue has that shape, so the theorem still applies —
but it is now a claim about our queue, and the constants in `ci/merge-queue.toml` describe
that queue. Nothing here proves the gates themselves are right, and nothing here changes what
a Required gate is; it changes who decides that a Required gate held, and whether that decision
can be checked later.

## Rollback

Restore the branch-protection contexts and re-create the `merge_queue` rule, then set
`owner = "github"` and `strict = false`. It is two API calls and a three-line revert, and the
required contexts on the workflows never moved, so nothing else has to come back with it.
