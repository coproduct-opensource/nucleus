# Trusted workload namespace setup (2026-10-22)

Gatehouse's converted Rust gates previously ran `unshare` inside the workload shell to establish private loopback and an inner UID. Nucleus correctly rejects workload-time namespace creation: a user namespace reacquires namespace-local capabilities. Authentic gate failures therefore stopped before Cargo with `unshare: Operation not permitted`.

The workload can now explicitly request `network_namespace: private_loopback` (or `private_offline`) and `user_namespace_uid: 1001`. These options require MicroVM containment. They are absent from legacy serialized specs. Unsupported containment, inner UID zero and the unmapped-ID sentinel are refused; failure to establish a requested namespace fails the spawn.

The trusted launcher creates the private network namespace and configures loopback before dropping privileges. Its private PID-namespace init installs a single UID/GID map into its waiting child, acknowledges success, and otherwise reports the setup error. For an outer workload UID of 65534, inner UID 1001 maps only to that existing unprivileged identity: scratch ownership and cache ownership do not change. Supplementary groups are cleared before mapping; effective, permitted, inheritable and ambient capabilities are cleared before the existing no-new-privileges, Landlock and syscall restrictions apply. No workload-time namespace syscall is enabled.

The applied namespace coordinates are included in the launch authority hash (schema 6), and the requested fields participate in the workload's program identity. A namespace request is not evidence until the hook and exec succeed.

On the temporary ARM64 Linux host (kernel 7.0.0-1014-gcp), the real child-spawn integration test verifies inner UID 1001, the exact single-ID map to 65534, writable outer-owned files, zero capability sets, a distinct network namespace, private loopback success only when enabled, failed external TCP connection, continued EPERM from unshare, and denial of a world-readable disposable control canary under the runtime's hidden /run tree. The initial unprivileged self-mapping attempt failed at uid_map write; no host policy was relaxed. The trusted init supplies the map instead.

Guest/gate receipt validation is a separate integration obligation. The private Gatehouse executor must request these fields, keep outer UID 65534, and use its existing shared prelude rather than attempting namespace setup in the confined shell. Existing signed failed gate receipts remain failures; rerunning requires the repaired execution environment and genuine new evidence.

The real UID-map mutation (omit the map at the trusted call site) fails with observed UID 65534 and an identity map; restoring the implementation passes. Strict Linux clippy passes for nucleus and nucleus-tool-proxy with all features and targets. Static musl compilation additionally exposed libc's differing ioctl request argument types; the hook uses the kernel syscall ABI on both libc implementations.

A full affected-workspace run also exposed an existing macOS loopback-probe readiness race. A bounded Rust reproduction hit EWOULDBLOCK at round trip 810: connect can return before nonblocking accept sees a queued peer. The probe now awaits accept readiness within its existing two-second bound. The unchanged reproduction then completed 2000 round trips; explicit delayed-peer and absent-peer tests preserve success and timeout distinctions.

## 2026-10-30: the lane on this branch's node, and three things in this tree

Gatehouse ran this branch's node (`f23df095c`, guest kernel 6.1.186) on the arm64 lane. The
launcher's private loopback and inner UID 1001 were realized, and `svid_key_later_fetch` was
refused. Three things in this tree still failed. All three reproduce in an Apple `container`
(arm64 Linux 6.18, Landlock and seccomp enabled), and the first and third are fixed here.

**`text-north-star`: `exec_noexec_run` could not look.** The canary staged its executable with
`tempfile::tempdir_in("/run")`. Since #3184, guest-init mounts `/run` as a root-owned `mode=0755`
tmpfs and creates everything under it with umask 077, so uid 65534 can create nothing there.
#3184 made `/run` safer and blinded this probe on every guest built after it. A probe that
counted "cannot create in `/run`" as refused would stop testing noexec, and a writable
subdirectory would still be a staging ground. A workload-writable `/run/user/<uid>` would give the
workload space on the tmpfs that holds the identity material, against the
`runtime_tmpfs_is_not_workload_writable_and_shared_tmp_is_sticky` decision. So the probe
(`nucleus-escape-canary/src/staging.rs`) now searches every directory under `/run` it can reach.
If one accepts a file, it stages there and requires `EACCES` at exec. If none does, every create
must have been refused with `EPERM`/`EACCES`/`EROFS`, AND `/proc/self/mountinfo` must show every
mount at or under `/run` as `noexec`. A directory it can search but not list is could-not-look.
Measured as uid 65534, with the old and new canary on the same `/run`:

| `/run` | old | new |
|---|---|---|
| 0755 root, 0700 children, noexec (the guest) | could-not-look | refused |
| plus a writable `/run/user/65534`, noexec | could-not-look | refused (staged, exec `EACCES`) |
| writable subdirectory, `/run` remounted exec | could-not-look | breach |
| nothing writable, `/run` remounted exec | could-not-look | breach |
| a `--x` directory, noexec | could-not-look | could-not-look |

**`test-node`: two `child_seccomp` attribution tests.** Each asserts that an unconfined control is
not answered `EPERM`, so that the confined child's `EPERM` is the filter's. A gate step already
runs under the launcher's filter, which denies AF_VSOCK and ptrace to the control as well. Under a
confined parent (the same `HostHardened` confinement applied to the test binary), both failed on
the old tests. When the control is denied and this process carries a filter, the tests now still
assert the confined child's `EPERM`. They attribute it by filter count instead (exactly one more
than this process), and print `UNATTRIBUTED <op>` to stderr, which `.config/nextest.toml` shows
for this binary. A denied control with no filter of its own still fails. Red: 9 passed, 2 failed.
Green: 11 passed, both unconfined and under the confined parent.

**`test-node`: three `child_workspace` tests.** The cause was `CARGO_TARGET_TMPDIR`, not `TMPDIR`.
A gate's target dir is `/cache/target`, so the test workspace landed in `/cache/target/tmp`,
inside the write layer's scratch `/cache`. `workspace_parent` held its own copy of the scratch
list (`starts_with("/tmp")`), and that copy never learned about `/cache`. It now asks
`preflight_filesystem` about each candidate (the target tmp dir, `/var/tmp`, `HOME`) and takes the
first one every posture accepts. Reproduced as uid 1001 with `CARGO_TARGET_DIR=/cache/target`,
`HOME=/work` and `/var/tmp` unwritable, as on the lane: red 2 passed, 3 failed, with the lane's
message. Green: 5 passed.

**`clippy-libs`, `test-libs`: `scripts/gatehouse-verifier-sdk.sh` needs a mount. Not fixed here.**
The script bind-mounts the checkout at the canonical builder's path `/data/work/nucleus/nucleus`
with `unshare -Urm`, because the wasm embeds source paths and the pin is that builder's bytes. The
trusted launcher denies a workload `unshare`, as it should. Each replacement that needs no
privilege was measured: `cargo build --release --target wasm32-unknown-unknown` of
`sdks/verifier-js` (rustc 1.96.1, arm64), all on one builder, comparing the `.wasm`:

| build | sha256 (first 8) | equal to the bind? |
|---|---|---|
| A: bind at the CI path (the script today), twice | `b4981bc1` | itself, both times |
| E: A plus a RUSTFLAGS no-op remap | `b4981bc1` | yes: RUSTFLAGS do not move `-C metadata` |
| F: A with `CARGO_TARGET_DIR` elsewhere | `b4981bc1` | yes: the target dir is not embedded |
| C: in place, at `/work/src` | `bef3386a` | no: the source path is embedded |
| D: in place, `--remap-path-prefix=/work/src=/data/work/nucleus/nucleus` | `69077704` | no |
| D': the same remap from `/srv/elsewhere/checkout` | `49fc4c43` | no, and not equal to D |

D embeds exactly the same path strings as A, yet has 13 more functions in its code section, and
wasm-bindgen's `_bg.wasm` of it differs too (the `.js` shim does not). D and D' show that a remap is
not even path-independent, so remapping on every builder would not yield one digest either. A copy
cannot reach the CI path: it is a root-owned directory on the read-only rootfs. A symlink changes
nothing cargo sees, because cargo reads its physical working directory. So the source has to
physically be at the CI path. That needs either a launcher request (the trusted launcher binds a
workspace directory onto an existing empty rootfs directory in the workload's private mount
namespace, which it already creates for the PID namespace), with a Gatehouse plan field to ask for
it, or a second pinned digest for the lane's in-place build, which every later SDK change would have
to mint from a lane run. That choice is open.

**Wrong belief corrected.** That "pointing cargo somewhere else" would move the bytes (this
script's `SDK_TARGET` comment). F shows the target dir location does not. Only the source path
does.
