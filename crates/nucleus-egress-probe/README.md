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

A fence that blocks everything (dead NIC, unconfigured loopback, a probe that
cannot run) trivially passes a "connect fails" check. The probe carries a
**positive control** beside the refutable negatives:

- **positive control** — a loopback connect the guest MUST be able to make (the
  default-deny chain accepts `-o lo`). If it fails, the probe reports FAIL: it
  will not certify a fence it cannot distinguish from a dead network.
- **negative posture** — a raw TCP connect to a non-allowlisted host and a DNS
  resolve of an off-allowlist name, which MUST both fail.

PASS requires the positive control to succeed AND every negative to fail.

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
when loopback is also blocked (the vacuity guard — a dead net must not read as
confined).
