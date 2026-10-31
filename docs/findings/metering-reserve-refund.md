# Reserving a metered call's ceiling: what deploying it found (2026-10-31)

The change is this branch's `9acc0977b`: a metered upstream call reserves its worst-case price
(`Metering::ceiling`) before any credential is minted, and settles down to its real price after.
These are the facts found while deploying it to a pilot node. The deployment record itself is
kept by the operator, outside this repository.

## 1. This branch's base is not the deployed node's lineage

The wrong belief: "the pilot node runs `3ee48704b`, so a branch cut from `3ee48704b` is the node
plus the fix." The node had moved on by three commits that exist only on a local backport
branch: a review-gated write fix, a test fixture fix, and the revocation-watch deadlock fix
(#3510, cherry-picked). Building this branch as it stands would have shipped the reservation and
silently removed #3510, which is the fix for a node that froze on a cancel during an in-flight
call. Checked with `git log 3ee48704b..<deployed commit>` (3 commits) against
`git log 3ee48704b..fix/metering-reserve-refund` (2 commits, this fix and a vendor note).

`main` does not contain the deployed lineage either. Of the 18 commits between the deployed
lineage's merge base with `main` (`5f5b14745`) and `3ee48704b`, `git cherry` matches none by
patch id, and a subject search finds 7 squash-merged into `main` under PR numbers. The other 11
are only on pilot branches, among them `3ee48704b`, `5c752e551` (metered pricing), the teardown
bounds (`9dbe19340`, `d725068e3`) and the tool-proxy `/v1/policy` route (`15d87ceaf`,
`8bf3ca3b8`). So rebuilding the node from `main` plus this fix would also drop them.

What was deployed instead: the deployed commit plus `git cherry-pick -x 9acc0977b`. It applied
cleanly, and `git patch-id --stable` is `76833b4c…` for both the original and the pick, so the
deployed change is exactly this branch's.

## 2. Red on the deployed code, green with the fix

Both runs on arm64 Linux (`rust:1.96.1-bookworm`), each in its own fresh target directory.

- **Red.** The deployed commit, with only `broker_perform/tests/reserve.rs` and its three
  `#[cfg(test)]` helpers added (`PodPolicy::budget`, `RegistryEntry::with_metering`,
  `Metering::live_rates`). All 4 buffered-path tests failed, exit 101:
  `a_pod_with_less_than_one_ceiling_left_is_refused_before_upstream_io` ("granted"),
  `a_call_holds_its_ceiling_in_flight_and_settles_down_to_its_charge` (balance 1 during the call,
  expected 0.754228), `concurrent_calls_cannot_both_reserve_past_the_budget` and
  `the_ledger_is_the_sum_of_charges_and_the_crossing_call_is_refused`. The streamed-path test
  was not run red on this base; it was red on `3ee48704b`.
- **Green.** The deployed commit plus the pick:
  `cargo test --locked -p nucleus-node --all-features` exit 0, 1151 passed, 0 failed,
  21 ignored, and olog 3 of 3. That is the 1141 of the base plus the 10 new tests. The deadlock
  test `a_connection_revoked_mid_call_drops_its_call_without_holding_the_revocation_watch`
  passed in the same run.

## 3. Rolling back past this change is not always a binary swap

The pod budget checkpoint (`pod_authority/budget.rs`, `Checkpoint`) is
`#[serde(deny_unknown_fields)]` in the code before this change. This change adds
`overrun_micro`, written only when nonzero, that is, only after an `ALARM: a metered call cost
more than the ceiling it reserved`. A node rolled back to the earlier code would refuse to
restore a pod whose checkpoint carries it. With no overrun, the file has the old shape and a
rollback reads it. The checkpoint's `consumed_micro` does include holds of calls in flight at
the time it was written, so a pod restored by the older code is charged those calls' ceilings,
which is the conservative direction.

## Still open (from the change's own notes, unchanged by deploying it)

- The buffered path never calls `body_complete`, so a buffered metered call is settled
  `UsageUnreadable` and charged its ceiling, not its price. Only the streamed path prices.
- Pod release under `settle = "metered"` reads the ledger snapshot, which leaves out holds; a
  call in flight at release is charged after the parent has folded the pod's spend.
