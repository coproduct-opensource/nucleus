# Guest escape canary

A fail-closed Rust replacement for the original Python gate canary. It is the
first step of the `text-north-star` gate, which inherited the single text-gates
gate's scope when that gate was split (`.gatehouse/pipeline.writ`). The step names
`cargo run --offline --locked` for this crate, with two build jobs, no incremental
compilation and no debug information. Its compiled output is confined to target/**.
The pinned elaborator accepts the declaration, and an isolated flight measured its
fit (below). Run the binary only inside a disposable
Nucleus guest with `--in-disposable-guest`: a successful mount, ptrace or device
probe has real effects. The kernel command-line check reduces accidental host
execution; it is not an isolation proof.

The 19 probes cover public TCP, TCP/UDP DNS, name resolution, metadata access,
base writes, host credentials, kernel command line and init environment, writable
noexec layers, mount/raw-socket/device privileges, foreign processes, ptrace and
later SVID fetches. Probe names and dispatch share one exhaustive enum. Exit 0
requires every probe to report refusal; breach exits 1 and incomplete evidence
exits 2. Any breach dominates incomplete observations. An empty run fails.

## Network evidence

The active probe alone is insufficient. The canary enumerates kernel interface
flags before and after the probe, requires a nonempty inventory containing only
IFF_LOOPBACK interfaces, and checks that both snapshots refer to the same network
namespace. Open namespace handles stay alive across the attempt. Missing evidence,
a non-loopback interface or an unfinished probe fails closed. A successful active
probe is a breach even if the inventory disagrees. Socket timeouts and errno values
without topology evidence never pass.

This requires the ordinary gate guest to have no virtual NIC. Gatehouse PR #260
changes gate specs from an empty NetworkSpec (a NIC plus deny-all firewall) to
an absent NetworkSpec (no NIC). The canary does not create a stronger namespace
for itself. Two snapshots do not prove that a privileged adversary never changed
topology between them, and the network probes do not cover every possible covert
channel. Their trusted base includes the guest kernel and the host's VM configuration.

## Other evidence limits

The SVID probe rejects a key leaked on either workload fetch and never prints reply
bytes. A kernel-denied identity channel is recorded separately from testing the
one-shot key latch. Unavailable services and malformed responses are inconclusive.
Permission-sensitive probes preserve errno; missing mount targets and missing
executable interpreters are not denials. Scratch objects use exclusive owned paths.
A successful mknod is a breach even if reading that device later would fail.

Pure regression tests cover classification and topology decisions. Linux cross
Clippy checks compile the effectful implementation but do not execute it. Before
live wiring, validate the complete canary and weakened controls in isolated guests,
measure compilation against the gate's resource budget, regenerate the pinned
plan, and verify fresh receipts from the uploaded plan. A passing check against
the old uploaded plan does not validate this canary.

## Measured controls, 2026-10-04

The ARM64 static binary was run in two fresh Apple `container` Linux guests,
using Alpine index digest
`sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8`.
Both ran as uid/gid 65534, with all capabilities dropped, a read-only root,
noexec/nosuid/nodev tmpfs at /tmp and /run, and only the test binary mounted
read-only from the host. The explicit `nucleus.canary_control=1` boot marker
allowed these deliberately non-Nucleus controls past the accidental-host guard.
This marker is not evidence of Nucleus confinement.

- External networking: 19 observations, exit 1. Public TCP, TCP DNS, UDP DNS
  and name resolution all reported breaches. Metadata was inconclusive.
- `--network none --no-dns`: 19 observations, exit 2. All five network probes
  reported refusal with loopback-only evidence. The absent /opt/nucleus-build
  and absent SVID service remained inconclusive, as expected for Alpine.
- Both guests were removed; a subsequent container inventory contained no
  `nucleus-canary-control-*` guest. Existing containers were untouched.

The first control exposed tempfile's path-context wrapper losing raw_os_error,
which incorrectly made real EROFS/EACCES inconclusive. The write probe now
reserves a unique name separately and uses OpenOptions::create_new directly.
The first no-network run also exposed the five-second DNS observation deadline
expiring before libc's resolver returned. DNS now has its own 30-second bound;
an unfinished lookup still fails closed. The corrected controls were rerun.
The guard checks /proc/self rather than requiring PID 1 to remain visible;
Nucleus intentionally hides another uid's PID 1 with hidepid=invisible.

These controls exercise the Linux implementation and its negative controls.
They do not validate the Gatehouse executor, a Firecracker launch, the SVID
latch, compiled gate resource usage, or signed receipt verification.

## Isolated Firecracker flight, 2026-10-08

The canary ran as declared, inside an ordinary gate guest, on an isolated
x86_64 lane: the non-production onboarding lane, its worker pointed at a local
control plane with throwaway log, node-CA and bearer keys, source from a local
mirror, and the GitHub API at a closed port (the shape of gatehouse's
`ops/x86-lane/acceptance/run.sh`). The lane ran gatehouse 7ac8bd697, which is
gatehouse#260: gate guests get no network interface at all. The plan was the one
`scripts/gatehouse-plan-body.py` builds at the pinned gate ref, plan
`8bb768b7...` with the provisional 1800 s timeout; the five unseeded required
gates were dispatched, and the five seeded ones were left optional because that
lane holds no seeds.

- `text-north-star` held. All 19 probes reported `refused`, the five network
  probes each with loopback-only inventories in one namespace before and after,
  and `svid_key_later_fetch` refused. The receipt verified at NodeAttested.
- Budget, cold and unseeded, at 2 vCPU, 2048 MiB and 4096 MiB scratch: the canary
  step took 32.3 s from launch to verified artifact retrieval, 23.2 s of it in
  the pod with the build included. The ledger step took 13.1 s and the whole
  attempt 56 s, against the 360 s timeout the gate keeps.
- The pod spec carried no network section and the guest's interface inventory
  held `lo` only. On the previous controller, the same guest had `eth0`
  (gatehouse `docs/gate-network-boundary-2026-10-04.md`).

This flight validates the canary on one lane and one kernel. It does not
replace the production check after the plan upload: the first production
`text-north-star` receipt must show the same 19 refusals.

## The plan production serves (2026-10-08)

Main's push of #3106 set plan `4650b95e…`, not the flight's `d71f62c2…`: main
had also taken #3330 (the seeded gates' new seeds) and #3339 (`inFlight` 3).
Neither touches `text-north-star`. Its definition
(`.gatehouse/gates/text-north-star.json`) and the shared environment are
byte-identical to the second flight's, so the flight exercised the gate
definition production now serves. The plan hash differs only through other
gates and the policy. Before the upload, every production lane already ran
gatehouse#260's controller (`81dc382c…`). Its 25 gate pods from the
rollout had no network interface, and the #3106 merge group's ten required
gates held on it, verified at NodeAttested.
