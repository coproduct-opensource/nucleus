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

## 2026-10-30, later: the launcher binds the workspace (owner decision "Launcher bind")

The owner chose the first way above. `WorkloadSpec::workspace_bind {source, target}` asks the
trusted launcher to show a directory of the work dir, read-only, at an existing empty directory of
the image. The init (pid 1 of the workload's PID namespace, still root, in the private mount
namespace it already makes for `/proc`) binds `source` over `target` and remounts the bind
`ro,nosuid,nodev,noexec` before it forks the workload (`crates/nucleus/src/hardening/pidns.rs`).
Workload `unshare` and `mount` stay denied.

**What is refused, and where.** Admission (`WorkloadLaunch::admit`) refuses a bind off MicroVM
and checks it with `WorkspaceBind::compile` (`crates/nucleus/src/hardening/bind.rs`) before the
confinement, so the forked init only mounts:
- `source` must be relative plain names, resolve inside the work dir with no symlink on the way,
  and be a directory;
- `target` must be absolute plain names, strictly under `guest_layout::WORKSPACE_BIND_ROOT`
  (`/data/work`), an existing directory that is not a symlink, reached by no symlink, empty, and
  on a read-only filesystem (so its emptiness cannot change before the launch);
- the two must not overlap. A test holds that nothing the guest layer reserves lies at or under
  `/data/work`.

The hook refuses a bind without the workload's own PID namespace (there is no private mount
namespace then). The launch receipt's preimage gained `bind=` (schema 6 → 7).

**Red, then green.**
- `bind.rs` unit tests against an accept-all `compile`: 8 failed, 1 passed (the positive case).
  Real code: 10 passed (the reserved-root test added after a Linux run: the first draft also
  asked `reserved_by` about each target, which refused every `/tmp` fixture on Linux, so the
  check moved to the root, where it belongs).
- Tool-proxy admission (`workload_network_tests.rs`) with the bind checks removed: 2 failed.
  Restored: 640 passed on macOS, 683 passed and 1 ignored on Linux as root.
- `tests/workspace_bind.rs`, root Linux (Apple `container`, arm64, kernel 6.18.35, Landlock on):
  the child (uid 65534, MicroVM confinement) reads the work dir's bytes at the image path, gets
  `EROFS` writing there, and its mountinfo shows `ro,nosuid,nodev,noexec`; the runtime's
  namespace sees an empty directory and no mount. With the init's bind disabled it fails at the
  read; with the read-only remount disabled it fails at the `EROFS` assertion. Green: 3 passed.
  `child_seccomp`: 11 passed. Linux `cargo clippy -p nucleus -p nucleus-tool-proxy -p nucleus-spec
  --all-features --all-targets -D warnings`: exit 0 (two `large_enum_variant` expectations, for
  the bind's two path buffers in the `Copy` value the forked hook reads).

**The digests, through the new path.** Same builder as the table above (`rust:1.96.1-bookworm`,
arm64), `/data/work/nucleus` a read-only tmpfs with an empty `nucleus/` in it:
- **E1**, the table's build A by the launcher: `cargo build --release --target
  wasm32-unknown-unknown` of `sdks/verifier-js`, `CARGO_HOME=/home/runner/.cargo`, spawned by a
  throwaway harness through `ChildConfinement::apply_with_namespaces` with the bind, as uid
  65534. Twice: `b4981bc1de71551d…a5099d` both times, equal to A byte for byte. The runtime's
  `/data/work/nucleus/nucleus` stayed empty.
- **E2**, `scripts/gatehouse-verifier-sdk.sh` itself, in an emulated gate image (pins.json naming
  `/data/work/nucleus/nucleus`, a vendored registry, wasm-pack 0.13.1, its wasm-bindgen and
  wasm-opt cached as the image does). Old path: as root with no bind, so the script's own
  `unshare -Urm`. New path: through the launcher as uid 65534, twice, where `unshare` is denied.
  All three runs gave the same `_bg.wasm` (`4228ef55…`), the same `.js` (`8d29fea6…`, the pinned
  shim digest) and the same raw cargo `.wasm` (`a88b2dcd…`). The `_bg.wasm` is not the pinned
  `f35bafe6…` because this emulation's `rustc-ci-host` passes through to an aarch64 rustc and its
  registry path is not the image's; what the run shows is that the bind path and the unshare path
  give the same bytes. The new path's log names no `unshare`.

**What the script does now.** If the checkout is already at `ci_workspace` (`[ "$src" -ef
"$workspace" ]`, the launcher's bind), it builds there with `CARGO_TARGET_DIR` set to the SDK's
subdir and `wasm-pack --out-dir` the checkout's `pkg/`, because the bind is read-only. Otherwise it
runs the `unshare -Urm` path as before, for a lane whose runtime lets a workload unshare. The
wasm-opt memo keys on `-o`, so a seed minted by the old path misses it once (about 23 s).

**Not yet true.** A gate can ask for the bind only through gatehouse's plan (`Step.checkout_at`,
gatehouse `deploy/lane-launcher-bind-20261030`), and the plan gatehouse serves for nucleus is set
only by a push to `main` (`.github/workflows/gatehouse-plan.yml`, `plan-upload`). Until that plan
declares the bind on step 0 of `clippy-libs` and `test-libs`, those steps reach the script with
no bind, and on a trusted-launch lane its `unshare` is refused as before. Nothing here has run on
the lane.

## 2026-10-30, evening: `exec_noexec_run` is decided by the mount table, and names its paths

On the lane, this branch's `9e7b2c870` (tree `c0b76edd`, node `9e7b2c870`) still failed
`text-north-star` (leaf 18056, exit 2): `exec_noexec_run` answered could-not-look, "a directory
can be searched but not listed". The real guest's `/run` has a directory that uid 65534 may enter
but not read, and the probe stopped the search there and did not say which directory it was. The
emulated layouts above had no such directory. That is gatehouse F-331.

**Wrong belief corrected.** That the search decides, with the mount flags as a fallback for "found
nothing". The property is noexec, and `/proc/self/mountinfo` states it per mount. A file under
`/run`, hidden directory or not, lives on some mount at or under `/run` (a symlink out of `/run`
leads to another mount, which other probes cover). Every such mount is in the table, so if each
one is `noexec`, a directory the search cannot list cannot hide a file the kernel would execute.
So the mount table now
decides first (`staging::runtime_exec_denied`):

- a mount at or under `/run` without `noexec` is a breach, whatever the search found. Before, a
  staged exec denied `EACCES` beside such a mount was refused, and an incomplete search beside it
  could-not-look;
- a staged payload that ran is a breach, whatever the table says;
- a searchable, unlistable directory is recorded and the search goes on, so a writable directory
  beside it is still found and tested directly. With every mount `noexec` and nothing seen
  writable it is refused. With the table unknown it stays could-not-look. It is never counted as
  empty;
- the record now carries `detail`, naming the hidden directories, the staged path, or the mount
  point that is not `noexec`.

Every mount listed at or under `/run` counts, including one the workload could not reach by path
and one covered by a later mount: that only makes the answer stricter. Not covered: a mount
elsewhere that shows the same tmpfs without `noexec` (a bind of `/run`'s superblock at another
path). The probe is about the paths under `/run`, and `exec_noexec_tmp` and the rootfs write
probes cover the others.

**Red, then green.** The new tests against the old behaviour behind the new interface: 6 of 28
failed. Against the tempting weak fix (a hidden directory refused without asking the table): 4 of
28 failed, among them `a_hidden_directory_beside_an_exec_mount_is_a_breach`. Green: 28 passed on
macOS, and 28 passed on Linux as uid 65534. End to end, the canary binary as uid 65534 on a
Linux tmpfs `/run` in an Apple `container` (arm64), each layout with `/run/nucleus` 0700 root
and `/run/hidden` 0711 holding a 0777 `inner`:

| `/run` | `9e7b2c870` | this change |
|---|---|---|
| nothing writable, all `noexec` (the guest's shape) | could-not-look | refused, names `/run/hidden` |
| plus an exec tmpfs at `/run/user/65534`, not writable | could-not-look | breach, names `/run/user/65534` |
| `/run` itself without `noexec` | could-not-look | breach, names `/run` |
| a writable `/run/user/65534`, `noexec` | could-not-look | refused, staged there, exec `EACCES` |
| a writable exec tmpfs at `/run/user/65534` | could-not-look | breach, the staged file ran |
