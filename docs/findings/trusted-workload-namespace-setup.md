# Trusted workload namespace setup — candidate, 2026-10-22

## Unsafe-boundary review checkpoint

The first required prepush failed the exemplar unsafe-site ratchet (8 to 14).
The initial helper added three unsafe functions and three unsafe blocks. Rather
than raise that threshold, the follow-up uses the existing rustix dependency's
typed identity, dumpability, capability, random-byte and descriptor APIs. This
removes the local capset ABI structs and raw buffer pointer/length calls. The
thread/rand features are enabled on the existing pinned dependency.

Two production unsafe blocks remain. Namespace creation uses only NEWUSER/NEWNET,
never FILES, so it cannot invalidate another thread's descriptor table (the
explicit rustix unshare safety obligation). The loopback ioctl initializes the
entire ifreq, writes a terminated fixed interface name, uses the flags union
member for both matching ioctl requests and closes its locally owned socket on
every normal return. Kernel rejection fails the spawn; no workload executes on
a partially installed contract. These are review arguments, not a proof of the
whole execution boundary. The unchanged ratchet still needs to assess these sites.

The post-fork path uses fixed stack buffers and syscall wrappers; allocating
formatting, proc parsing and the mapper thread run in the parent. Mapping is
bounded by socket timeouts and a one-use nonce exchange. A failed or dropped
prepared command can retain its mapper thread until timeout; per-command setup
threads and preparation-time deadlines remain resource/lifecycle limitations.
Review also found that flags-zero getrandom could wait for initial kernel RNG
seeding outside the socket timeout. Nonblocking kernel randomness now refuses
instead; there is no deterministic nonce fallback. Normal initialized-kernel
tests do not exercise an unseeded kernel. Socket timeouts still do not establish
a hard wall-clock bound on kernel scheduling, proc I/O or all spawn work.
Parent-side SYS_ADMIN remains required in the tested backend. This review does
not establish minimal parent capabilities or complete cancellation semantics.

All ten real syscall integration tests passed after the change: UID0/1000 with
loopback down/up, no retained capabilities, and confinement still enforced.
All five mapper unit tests passed with ignored backend-specific cases explicitly
included: real non-dumpable mapping, wrong outer identity and stale nonce refusal.
The unchanged exemplar measurement is now 10 versus baseline 8; it remains red.
Complete consumer follow-up suites and public prepush remain required before release.

Command-reuse review added a real first-success/second-spawn regression. It
failed: the second spawn returned a handle rather than reporting setup refusal.
Removing MSG_NOSIGNAL in a confirming falsifier observed wait status 13 (SIGPIPE).
std resets SIGPIPE before the hook, so writing a closed mapper channel could
terminate the child before its error reached std's status pipe. Nonce validation
still prevented executing a reused mapping; this was incorrect failure reporting,
not evidence of a successful second exec. The request now uses rustix send with
MSG_NOSIGNAL and propagates the error. All six mapper tests pass with the guard
restored, including actual successful setup followed by command reuse refusal.

Workload seccomp correctly denies user namespace creation. A workload cannot
perform declared isolation setup after that filter has been installed. Setup
must run in trusted code before Landlock/seccomp, with the resulting contract
bound to admission and launch evidence.

Self-mapping after std's root-to-workload UID drop failed at `uid_map` with
EACCES in a native Linux verification container. Temporarily enabling dumpability
made the experiment pass but changes process visibility during pre-exec. That
diagnostic was removed. The candidate instead keeps the child non-dumpable and
uses a private, bounded mapping exchange with the trusted parent.

The parent checks child parentage, all outer UID/GID values and empty supplementary
groups before installing exactly one mapping. It pins the child's proc directory
so an exited child's numeric PID cannot redirect later writes. Only a success
acknowledgement permits child setup to continue. The child raises private loopback only when requested,
locks NOROOT and clears effective, permitted, inheritable and ambient capabilities
before the ordinary hardening sequence. The channel is close-on-exec and one-use;
preparing a command starts a five-second setup window, so delayed or reused commands
can fail closed. This is a candidate API limitation, not an authority extension.

Command reuse requires more than a success byte: an acknowledgement delayed beyond
an earlier child's timeout can remain queued. The exchange now carries a fresh
16-byte per-fork kernel-random nonce, echoed with success/refusal. A test supplies
a stale nonce with success and no mapping, choosing inner 65534 (also Linux's usual
unmapped-ID observation). It refuses before exec. Removing the nonce comparison
made the test start the child and fail; the comparison was restored. Observed UID
equality alone is therefore insufficient evidence that a mapping was installed.

The sealed `Hardened` record now describes the installed hook's namespace setup.
The candidate launch authority-inventory schema is version 4 and commits its
canonical spelling. The same description now reaches V2 signed execution and
independent expectations, described below.

Native Linux verification with SYS_ADMIN in the trusted parent passed for inner
UID/GID 0 and 1000. Without that parent capability mapping was refused. The workload
did not retain those capabilities. The integrated `child_seccomp` regression checks
both identities, empty capabilities, usable loopback/fork, denied further user
namespaces through unshare/clone, and a derived prohibition on internet sockets.
Temporarily omitting filter installation made that regression fail: namespace
creation returned success instead of EPERM. Enforcement was restored; the full
affected ten-test integration suite passed. Standalone helper tests additionally
refuse an outer identity different from the prepared mapping.

The candidate public `WorkloadSpec.namespace` now requests runtime placement or
private user/network namespaces with an inner UID and required loopback state.
Runtime placement preserves prior serialized
wire shape. Admission consumes that request into core confinement; unfiltered
tiers and the reserved unmapped UID are refused. The real tool-proxy spawn test
now uses this request path rather than changing its admitted plan directly.
Program identity commits the request. All 210 spec tests and all 30 workload-module
tests passed in the native Linux verification backend with all tool-proxy features.
The first strict-parsing test caught Serde accepting extra fields on an internally
tagged unit `runtime` variant despite deny_unknown_fields. Using an empty record
variant makes the existing derived parser reject those extra fields; the test
then passed. No handwritten parallel parser was added.

Consumer review exposed a missing case in the initial always-up loopback primitive:
an isolated step can request a UID remap while leaving loopback down. Generalizing
the unreleased request/evidence to PrivateUserNetwork with an explicit loopback
boolean preserves that case. Both states are enforced before confinement and bound
in program identity, launch commitment and signed expectations. Native tests cover
inner UID 0/1000 with loopback down/up: TCP returns ENETUNREACH when down, works when
up, and derived denial still returns EPERM. Temporarily raising loopback regardless
of request made this regression fail; the conditional was restored. The normal
Runtime wire shape remains unchanged.

Candidate signed execution is now V2 and carries the same NamespaceSetup type as
the launch hook and supervisor observation. The node compares the observation with
its admitted spec before signing. The independent verifier compares the signed
setup, including both mapped IDs, with separately supplied expectations. V1 and
missing setup evidence remain parseable for inspection but cannot satisfy V2
acceptance. A missing legacy expectation becomes Unrecorded, which is refused.
Admission metadata describes the desired setup separately from execution evidence.
The shared type lives in the existing execution-projection crate; the spec imports
it rather than creating a second wire description or making the offline verifier
depend on the policy/runtime stack.

Verification: the five node signing-preparation tests passed, including matching
program identity with mismatched namespace setup. Removing the independent
verifier's namespace equality made its signed-wrong-setup regression accept the
wrong claim and fail. The guard was restored. The complete execution-projection
crate passed 28 tests and three compile-fail doctests; the final spec, core syscall
and workload suites passed 210, 10 and 30 tests respectively. These test results
do not demonstrate a live microVM emitting the new signed claim.

This is not a released contract. Consumer adapter integration, complete caller
validation and a live signed execution campaign remain unfinished. Private
network placement disconnects runtime loopback TCP services; it does not supply
a service binding or a universal agent environment. Kernel capability requirements, cancellation,
timeouts, command reuse, resource accounting and the new unsafe boundary still
need review. No general confinement theorem or least-privilege claim follows from
these tests. The existing default workload path retains its filter.
