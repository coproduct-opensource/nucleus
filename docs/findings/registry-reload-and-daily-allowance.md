# Renewing a federated binding without a restart: what the work found (2026-10-12)

The change: `nucleus-node` re-reads its `--upstreams` registry (the `[[upstream]]` entries and the
`[[caller]]` bindings) on SIGHUP and whenever a poll sees the file's SHA-256 change
(`--upstreams-poll-secs`, default 10), with start-up's validation. A file that fails keeps the
registry in force and is reported by digest in `/v1/health`. A binding may set
`max_cost_usd_per_day`, enforced at admission per UTC day beside the ledger. Design:
`crates/nucleus-node/src/pod_authority/registry.rs` and `pod_authority/daily.rs`. Tests:
`crates/nucleus-node/src/federation_ingress/tests/reload.rs`.

It was driven by an operator who renews a pilot binding's window (at most an hour) and raises
its budget by editing the file, and who until now had to stop the node, edit, and restart for
every renewal. Measured on `origin/main` at `5e8f7c85a`.

## 1. Raising a binding's `max_cost_usd` never raised its budget, not even across a restart

The wrong belief: "the registry's ceiling is the binding's budget; edit it and restart to raise
it." In fact a binding's ledger was created with the ceiling of the moment it was first charged,
persisted as `max_micro` in `authority/external/<key>.json`, and on every restart restored from
that file. Nothing ever read the registry's ceiling again. A raised ceiling admitted nothing more,
and a lowered one bound nothing.

Driven red on unmodified `main` (the test below, with only the fields this change adds removed):

```text
federation_ingress::tests::reload::a_raised_ceiling_applies_across_a_restart_too ... FAILED
the registry's raised ceiling binds after a restart:
  Authority("budget conservation: budget conservation: requested 1000000 µUSD, parent can allocate 0 µUSD")
```

The fix: at each admission under a binding, its ledger's ceiling becomes
`max(registry ceiling, consumed + allocated)` (`receil`). Consumption and the retired list are
carried over exactly, and the test checks the persisted `ledger` record is byte-identical before
and after. A ceiling lowered below what is already used admits nothing more and clamps nothing
away; it does not refund. `BudgetLedger` has no way to move its ceiling, and its core is the Kani
proof subject, so the ledger is rebuilt and checked equal (consumed, allocated, live children)
before the swap. A mismatch refuses the admission rather than guessing.

## 2. A reload is a replay window unless the replay cache survives it

Found while building the reload, not on `main` (which had no reload). Each binding's
`ExternalIssuerValidator` owns the cache that makes a token single-use. A reload builds new
validators, so a naive one hands every token already exchanged a second use for the rest of its
life. The same holds in the other direction: an exchange still holding the old validator while a
new one is in force.

The fix: `ExternalIssuerValidator::succeeding` shares its predecessor's cache when both name the
same issuer, and a token names exactly one. Driven red with the sharing removed:

```text
a_token_spent_before_a_reload_is_still_spent_after_it ... FAILED
called `Result::unwrap_err()` on an `Ok` value: ValidatedCaller { sub: "agent-session-1", ... }
```

Not fixed here: a node RESTART still starts every replay cache empty. That was true before this
change and stays true.

## 3. An exchange under a lapsed window still answers; the refusal comes at `POST /v1/pods`

Measured in `renewing_a_window_by_reload_admits_what_the_lapsed_one_refused`. With the binding's
inline `time.valid_until` in the past, `POST /v1/federation/exchange` still returns an SVID and a
delegation. The delegation carries the lapsed window, and the pod is refused at admission with
`delegation refused: lattice-level check refused mint_child: Parent permission has expired`. A
caller that classifies refusals (a "window" outcome) should key on that admission refusal, not on
the exchange. Changing the exchange to refuse is not done here.

## 4. A binding whose ceiling is a profile has a window stamped when the file is read

Read from the code, not driven end to end. `CeilingSpec::resolve` runs when the file is loaded,
and a profile's lattice carries `TimeLattice::hours(n)` from that moment. `codegen`, for example, is
`hours(1)`. So a `ceiling = { profile = "codegen" }` binding admits for an hour after the node
reads the file, then refuses every admission as expired. Before this change only a restart
renewed it. Now a SIGHUP renews it too, because it re-reads even an unchanged file. A poll does
not, because the file's digest has not changed. An operator who wants a window to last should
write it inline (`ceiling.inline.time`), which is what the pilot's renewal tool does.

## 5. Adding or removing a tenant on reload is refused, deliberately

A binding's trust domain is also wired into `AuthorizationPolicy::with_federated_trust_domains`,
which is built once at start. Swapping in a new tenant would admit a caller the policy does not
scope. Removing one would leave its still-valid delegations reaching admission with no binding,
where they would be held to a per-chain ledger bounded by the certificate's own budget instead of
the binding's. Not verified end to end; avoided by construction. A reload whose set of
`trust_domain`s differs from the running one is refused (`an_invalid_registry_on_reload_keeps_the_old_one_serving`),
so adding or removing a tenant is still a restart.

What a reload does not narrow at once: a delegation already exchanged keeps its capabilities and
window until its own `not_after`. That is at most `svid_ttl_secs` (≤ 3600 s), and never later than
the window the binding had when it was minted. Budget narrowing is immediate, because the ledger is
per binding and re-ceilinged at each admission.

## 6. The per-day allowance

`max_cost_usd_per_day` charges a pod's allocation to the UTC day of its admission. A pod that
never ran (an unspawned reservation, or a refusal after reserving) is credited back to the day it
was charged to. A pod that ran keeps its charge, matching the ledger, which folds its whole
allocation into consumption. Per-day totals persist in the ledger file as a version-2 `days`
map. A version-1 file loads as "nothing charged on any day", and an unknown version is refused as
unreadable. A day is charged whether or not the binding sets an allowance, so an allowance added
later counts the day's earlier admissions. Absent, there is no day dimension, and the ceiling alone
binds, as before. Driven red with the day check removed:

```text
a_spent_day_refuses_and_the_next_utc_day_admits ... FAILED
```

## 7. Verifying nucleus-node on macOS: two things that fail on `main` and are not this change

- `cargo test -p nucleus-node` does not compile on macOS:
  `firecracker_config_tests.rs::the_write_extent_is_the_widest_writable_drive_or_the_memory` calls
  `FirecrackerConfig::without_devices`, which is `#[cfg(target_os = "linux")]`. The local runs
  behind this note gated that one test to Linux in the working tree only. It is not part of the
  change.
- `cargo clippy -p nucleus-node -- -D warnings` fails on macOS in `crates/nucleus/src/hardening/landlock.rs`
  (Linux-only items, dead on macOS) before it reaches nucleus-node.

Both pass on Linux, which is where CI runs them. The Linux run for this change is recorded in its
pull request.
