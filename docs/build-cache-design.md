# Fast, verifiable Nucleus builds

Research and implementation checkpoint: 2026-09-12. This describes the build
experiment on `feat/nucleus-build-receipts`; it is not a production cache rollout. Run [34721798028](https://github.com/coproduct-opensource/nucleus/actions/runs/34721798028)
now demonstrates a complete cold/warm self-build at commit `9260327c8`.

The design is immutable inputs, private writable clones, and verification before
publication. Copy-on-write reduces storage work. Compiler caching reduces
compilation. Receipt reuse skips execution and needs a stronger equivalence
argument. These are separate decisions with separate measurements.

## Implemented in the experiment

`build-run` previously attached the same writable scratch inode to its cold and
warm VMs sequentially. It now gives each phase a separate disk. A private,
consumed `CompletedBuild` witness permits promotion only after successful artifact
verification and confirmed VM cancellation. The stopped ext4 filesystem undergoes
automatic journal recovery; an uncorrectable filesystem refuses promotion. The
resulting seed is read-only and hashed. Warm builds clone it, authenticate the
clone's bytes, and bind that initial scratch digest into the new program identity.
They still execute Cargo and require fresh execution and artifact verification.

Linux uses `FICLONE`; macOS uses `fclonefileat`. Unsupported filesystems or
cross-device placement use a reported sparse copy, with extent discovery where
available. Capacity and I/O errors propagate. Publication cannot overwrite an
existing destination and occurs only after digest verification. The temporary
publication link refers to the newly cloned inode, never the seed. These choices
follow the [Linux reflink contract](https://www.man7.org/linux/man-pages/man2/FICLONERANGE.2const.html)
and [Apple's clonefile contract](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/clonefile.2).

`cache.json` records the clone method, fallback reason, seed digest, logical size,
copy time, and verification time. Phase timing additionally separates preparation,
execution, checkpointing, and total time. The public evidence exporter includes
these records. The standalone probe runs without a node or KVM:

```sh
cargo build --release --locked -p xtask
target/release/xtask build-cache-probe --source /path/to/immutable-image --output /tmp/cache-probe-new
```

The probe authenticates copying against its input hash, not against an approved
build recipe. It grants no cache-promotion or receipt-publication authority.

Tests exercise independent writes to two clones, unchanged seed bytes, destination
collision refusal, corrupt-seed refusal without partial publication, and sparse
copy preservation of data and trailing holes. macOS tests exercise its native
clone path; the Linux branch is also cross-checked with the actual module and
rustix API. A real Linux reflink performance result remains to be collected.

## Measurements and limits

A 512 MiB synthetic image with 3 MiB allocated was measured on the local Mac.
Sparse copying took 7.9 ms; source hashing plus clone verification made the debug
probe take 5.196 s. With an optimized controller, the same probe took 0.410 s
(8.3 ms copying). This is approximately 12.7 times faster for this storage probe,
not a microVM build speedup. The experiment now builds and uses a release-mode
controller. Native APFS results are recorded alongside the implementation handoff.

The existing node snapshot implementation records a separate, earlier aarch64
measurement: approximately 17 ms restore/resume versus 79 ms cold boot. This does
not establish compiler-cache performance. The latest self-build failure before
this caching change reached Cargo inside a real VM, but failed because the image
omitted the egress sentinel and preserved unreadable vendor-file permissions.
Run 34721798028 subsequently verified both real microVM builds: cold total
225.740 s, warm total 88.779 s (about 2.54 times faster). Cargo reported 2m53s
and 41.71s; both binaries had the same SHA-256. The Linux filesystem refused
FICLONE with EOPNOTSUPP, so the reported warm path was sparse copy (2.946 s)
and digest verification (6.589 s). This proves exact-tree cache reuse through
its fallback, not Linux reflink performance. It does not prove reproducibility
across arbitrary hosts or source revisions.

A second run, [34723000387](https://github.com/coproduct-opensource/nucleus/actions/runs/34723000387),
completed the successor chain at exact source `58d894f18b891eccfacb5ee8ecf85a7ea63aa11a`.
The verified first-stage output ran as the next executor, with fresh signing keys.
Bootstrap cold/warm totals were 224.773/90.455 s; successor totals were
226.490/89.695 s. The successor's Cargo times were 2m51s/39.42s. All four outputs
were byte-identical and all four receipt/artifact bundles independently verified.
The successor warm path again used sparse copy: 3.018 s copying, 7.174 s verifying
an 8 GiB logical scratch disk. This repeats the roughly 2.5x exact-tree warm
speedup; native Linux COW and shared caches remain the next performance work.

Cancellation is not a guest filesystem flush. Journal recovery supplies a
crash-consistent seed and may lose recently written cache entries. A production
checkpoint needs a supervisor-controlled sync/quiescence protocol. Authenticating
the final binary does not authenticate every intermediate object in `target/`.
This seed stays within one exact-tree experiment and is not admitted to a shared
cross-tree or cross-tenant cache.

## Next layers, in order

| Layer | Design | Evidence required before enabling reuse |
|---|---|---|
| Materialized inputs | Content-addressed OS/toolchain/runtime and vendor layers; small immutable source data drive per tree | Complete recipe keys, atomic publication, eviction leases, digest mismatch refusals, bytes avoided per edit |
| Writable scratch | Frozen seed and per-attempt COW clone on a reflink-capable host filesystem | Real Linux clone result, clean checkpoint, concurrent clone isolation, bounded dirty-byte growth |
| Compiler objects | Pinned sccache, bounded local cache, then remote storage through a host-controlled broker | Hits/misses and non-cacheable reasons; approved writer scope; changed flags, environment, dependencies and macro reads invalidate |
| VM memory | Existing pre-personalization snapshot barrier and host-compatible derivation | Fresh identities/entropy/time on every restore; immutable memory for each clone's entire lifetime |
| Verified results | Existing action-key and receipt-store primitives, connected to miss/run/verify/store | Exact-input verification first; enforced read/environment bounds and sampled reruns before cross-tree hits |

Cargo tracks filesystem freshness using dep-info and timestamps; checksum freshness
remains an unstable feature. We observed wrong xtask binaries when sharing one
target directory across worktrees and repaired validation by rebuilding that crate.
That observation does not prove its root cause, but rules out blindly treating
such reuse as trusted evidence. Preserve fixed guest paths and exact-tree seeds
until input tracking has been demonstrated. See [Cargo's fingerprint implementation](https://doc.rust-lang.org/stable/nightly-rustc/cargo/core/compiler/fingerprint/index.html).

sccache requires Rust incremental compilation to be disabled. It cannot cache
crates invoking the linker, and procedural macros reading files have documented
correctness limitations. Its multilevel mode can backfill nearer caches and write
to multiple levels; those settings are not authorization boundaries. Keep remote
credentials outside workloads and enforce namespace/write policy at the broker.
Pin a release and validate these capabilities before enabling them. See
[Rust support](https://github.com/mozilla/sccache/blob/main/docs/Rust.md) and
[multilevel storage](https://github.com/mozilla/sccache/blob/main/docs/MultiLevel.md).

For raw disk images, filesystem reflinks are a better initial fit than putting a
large writable image behind OverlayFS: OverlayFS performs file copy-up on writes,
so that layout can move substantial data on first modification. Guest-level
overlays remain an alternative for source trees, with their own mount and identity
changes. See [the kernel's copy-up semantics](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html).

Firecracker already demand-maps snapshot memory privately and leaves disk files
to the integrator. Its state CRC is not authentication, and snapshot restore can
replicate userspace secrets even with kernel RNG reseeding. Keep Nucleus's barrier
before workload identity and writable scratch initialization. See the
[pinned Firecracker snapshot documentation](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/snapshotting/snapshot-support.md).

After optimizing the hasher, measure whether repeated whole-image verification
still dominates. fs-verity can authenticate immutable files on reads and expose a
constant-time measurement, but its Merkle digest is different from a whole-file
SHA-256. Adopting it requires an explicit identity schema and trusted digest
binding; never silently substitute one for the other. See
[the kernel's fs-verity documentation](https://docs.kernel.org/filesystems/fsverity.html).

## Acceptance for a shared cache

Measure cold, exact-tree warm, unrelated-edit, dependency-edit, toolchain/flags/edit,
and concurrent-build cases on the same runner class. Record p50/p95 total latency,
compilation/linking time, compiler hit reasons, network bytes, physical allocation,
clone/verification time, and storage eviction. Targets are set from that baseline,
not invented from the synthetic probe. Cache failure must degrade to an isolated
cold build or an explicit error, never a fabricated successful check.

Shared publication must be controlled by the trusted builder, with complete input
keys or independently verified entry provenance. A successful signature on the
final binary alone cannot make arbitrary cached compiler objects trustworthy.
This follows [SLSA's build-cache threat model](https://slsa.dev/spec/v1.2/threats).
GitHub caches are readable across some PR/fork scopes, so keep credentials and
private build inputs out of public cache exports. See
[GitHub's cache access rules](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).
