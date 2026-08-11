# nucleus-egress-probe

The C6 egress backstop, checked on the **real** guest.

`net::apply_default_deny` installs a netns/iptables default-deny OUTPUT policy
for every pod, and the Lean egress matcher (`EgressConfinementExtracted.lean`)
proves the rule semantics — but until this probe, nothing checked that the
policy is **actually applied inside a booted microVM**. The C6 ledger note calls
channels 5 and 10 (in-shell / raw-socket egress) `backstopped-only`: "fenced
only by a *documented* netns default-deny, not yet proven-applied-on-boot".

This binary runs as the workload inside a `network.allow: []` pod and asserts,
from a process running as the workload uid in the guest, that egress is
confined. It is the network twin of `nucleus-workload-probe`: zero dependencies,
a static musl binary baked into the rootfs, and its verdict is a
`NUCLEUS_EGRESS_PROBE: PASS|FAIL` sentinel on both stdout and stderr plus the
exit code.

## Anti-vacuity

A probe that reports PASS because it is *broken* — a no-op that never really
attempts a connect — certifies nothing. The verdict rests on two independent
witnesses:

- **positive control** — a `socketpair(AF_UNIX)` byte round-trip that MUST
  succeed. It proves the probe is a live process that can create sockets and move
  bytes, so a denied TCP connect is a *refusal*, not a broken binary. It is
  AF_UNIX on purpose: the guest workload runs with **loopback DOWN** (documented
  in `nucleus-guest-init`) and under `network.allow: []` there is no reachable TCP
  endpoint by design, so a loopback/on-net control cannot exist here; a socketpair
  needs neither an interface nor a route.
- **negative posture** — a raw TCP connect to ≥1 non-allowlisted hosts and a DNS
  resolve of an off-allowlist name, which MUST all fail. Refusing to pass when
  *zero* targets were probed closes the empty-target vacuous door.

PASS requires the socketpair witness AND ≥1 probed target AND every negative
failing.

## Bounded, non-hanging

A fully-fenced pod has no resolver, so `getaddrinfo` on an off-list name blocks on
its own multi-second timeout — long enough that the pod is torn down before the
verdict. The DNS check runs on a worker thread with a short join bound; "no answer
within the bound" is the expected fenced outcome. Connects use a short timeout.
The sentinel is emitted promptly (a few ms in a fenced guest, where the connects
fail instantly with `ENETUNREACH`).

## Configuration

Defaults target the public internet (what the real guest sees). Overridable so
the host-side falsifier `scripts/check-egress-probe.sh` can point them at a
hermetic peer it controls inside a netns:

- `NUCLEUS_EGRESS_PROBE_DENY_TARGETS` — comma-separated `IP:port` (literal only;
  the connect posture must not depend on DNS). Default `1.1.1.1:443,8.8.8.8:53`.
- `NUCLEUS_EGRESS_PROBE_DENY_NAME` — a hostname that must fail to resolve.
  Default `example.com`.
- `NUCLEUS_EGRESS_PROBE_TIMEOUT_MS` — connect timeout. Default `1200`.

## Falsifier

`scripts/check-egress-probe.sh` reconstructs the fence on real Linux (a netns
with the exact `apply_default_deny` rules) and asserts: the probe PASSes with the
fence present, FAILs when the OUTPUT policy is opened (fence removed), and FAILs
when it probed no targets (the vacuity guard — a probe that checked nothing must
not read as confined).
