# Runtime memory journal

The tool proxy accepts `--memory-store /private/runtime/project-memory.jsonl`
and `--memory-namespace project-a` (also `NUCLEUS_MEMORY_STORE` and
`NUCLEUS_MEMORY_NAMESPACE`). Both settings are required together. Without them,
memory remains process-local. The operator creates the parent directory with
mode `0700`; the proxy creates the journal with mode `0600`. The path must be
absolute and outside the agent workspace. Existing symlinks and non-regular
files are refused. One proxy holds an exclusive file lock for its lifetime.

Only the proxy may reach the journal. Its children (every `/v1/run` command and
the pod workload) are not held off it by Landlock: the child ruleset is the
guest layout's and applies only in a microVM, which provisions no memory. The
boundary is the uid. The proxy asks the same deciders the spawns ask which uids
its children get, and refuses to open a persistent journal, by name, when a child
would run at the proxy's own uid (the bare host tier: a non-root proxy given
`--unsandboxed`, as the local driver does with `--allow-local-driver`), or when a
child's uid owns the journal or its directory (that child could replace it).
A non-root proxy without `--unsandboxed` spawns no child at all, and a root proxy
drops its children to a distinct uid, so both may open one. The same check runs,
through the store layer's `ReachCheck`, for pinned readers and branch overlays:
on the directory before anything is created, and on the file before it is read.

The journal begins with a header naming the schema
(`nucleus.memory-journal.v2`) and the namespace. Each subsequent line is one
**commit**: `{version, parent_head, records, publisher, epoch, commit_hash}`.
`version` is the parent's plus one, and version 0 is the empty space, whose head
is a domain-tagged hash of the namespace. `commit_hash` is the new head: a
domain-tagged SHA-256 over the parent head, the version, each record's content
hash and label in content-hash order, the publisher binding and the epoch. Records
keep their own content hash, so publishing one changes no record hash. The
publisher binding and epoch are opaque here; the node will mint them per run.
Writes the proxy makes directly carry a fixed operator publisher and epoch 0.

Startup checks the namespace, then replays every commit: it must follow its
parent and hash to its stored head, and each of its records goes in admission
order through the same provenance validator used for new writes. It never
deserializes a pretrusted memory set. Reordered, dropped or edited commits,
missing parents, unavailable transforms, invalid provenance, malformed lines,
unknown header fields, and incomplete trailing writes stop startup. A header
naming any other schema is refused by name. The journal has a 64 MiB limit;
capacity exhaustion refuses additional writes.

### Versions, branches and publish

The store layer is `nucleus_provenance_memory::journal` and `::overlay`:

- **Pinned reader.** `PinnedSnapshot::open(location, pin)` replays the journal up
  to `pin = (version, head)` and owns the records it saw, so later commits cannot
  change what it observes. It refuses a version not yet published, and a pin whose
  head differs from the journal's. A truncated journal is a valid prefix by
  itself; only a holder of the later pin can detect the rollback, and the pinned
  reader does. The reader takes no lock and counts only newline-terminated lines.
- **Branch overlay.** `Overlay::open(path, journal, snapshot)` is a separate
  private file with its own lock. Its header names the namespace and the base pin,
  and each line is one record, admitted against base plus overlay. Reopening it
  over a different base is refused. Writes go to the overlay only.
  `patch()` returns the overlay's records that are not in its base. Two overlays
  over one base share the base and never each other's writes.
- **Publish (compare-and-swap).** `publish(patch, expected_head, publisher,
  epoch, validator)` refuses unless the head is `expected_head`. A stale base
  returns the current head, so the caller can rebase and try again. It then
  validates the **whole candidate**: the head plus the patch's records that are not
  already there. `StoreInvariants` refuses a lowered label, a key published after
  the patch's base that the patch did not explicitly resolve, and a candidate over
  the record or byte cap. The validator is a trait, so the memory-context kernel's
  candidate check can plug in. Every record must then re-derive from provenance.
  The commit is then one write, flushed and synced, before the new head is
  visible. Each patch can be under a cap that the two together exceed. Six
  records then six over a cap of ten is refused at the rebase.

### v1 journals

A v1 journal (`nucleus.memory-journal.v1`: header, then one record per line) is
first replayed and verified exactly as before. If that fails, the file is left
untouched. If it passes, the journal is rewritten as v2, and its version 1 commit
holds every v1 record in admission order. The rewrite goes to a locked staging
file beside it, which is synced, renamed over the journal, and then the parent
directory is synced. A crash at any step leaves either the original v1 file or the
complete v2 file. A leftover staging file is removed on the next open, and
reopening a v2 journal rewrites nothing. A pinned reader never migrates; it
refuses a v1 journal by name.

The format change is in the guest-side proxy. A proxy older than this change
refuses a v2 journal (`schema or namespace differs`) rather than misreading it,
so a pod that falls back to an older guest image cannot reuse a journal that a
newer one has migrated. The node does not depend on the journal format.

After taking its lock, every writer checks that the path still names the file it
locked (same device and inode). A writer that opened the old v1 file before
another writer's rename therefore refuses, rather than migrating an orphan.

The live memory-write handler spends its authority and validates a candidate
state. It then publishes the record as one commit on the current head, appending,
flushing and syncing it before it publishes the state or returns success. A
duplicate accepted record does not add another commit.
Any uncertain write latches the store unavailable for both writes and recalls
until restart; it cannot be hidden by serving a stale in-memory state. The commit
is synchronous under the memory mutex, with no await point, so a cancelled request
cannot stop it part-way. A panic during the write leaves the latch set. An
interrupted caller may have committed a record, so a retry remains
content-addressed and idempotent.

Recall uses the restored record's label through the existing flow-graph path.
The journal does not persist a promoted recall label or turn a saved record into
permission to act. Source assertions retain the existing provenance model;
storage adds no external attestation of their truth.

The operator owns the file and namespace assignment. This is single-proxy durable
storage, not a shared multi-tenant memory service. Firecracker provisioning of storage
across pod lifetimes, host-mediated memory authority, compaction and retention,
automated recovery of incomplete writes, and durable declassification burn
history still need implementation. A disposable guest root filesystem does not
become persistent merely by setting these options.

## Node-managed namespaces

A node may opt in with `--memory-root /private/runtime/memory` (or
`NUCLEUS_NODE_MEMORY_ROOT`). The directory must already exist, be private, and
be separate from the node's configured workspace root. A pod requests a store
with metadata label `nucleus.io/memory-namespace: project-a`; namespace names
contain 1–64 ASCII letters, digits, underscores or hyphens.

After authority admission, the node resolves the name to a **memory space** and
the **binding policy** that admits the pod (`crates/nucleus-node/src/memory_space.rs`):
the tenant's declared space of that name if there is one, else the pod's lineage's
own space for the name, created on first use under a `Lineage(root)` policy. A
spec cannot supply a host path, a tenant, a policy or an audience. The node then
mints the run its own binding (`memory_binding.rs`): it pins the space's head,
writes the run a private copy of that version as the policy's view sees it at
`<memory-root>/bindings/<binding id>/memory.jsonl` (a v1 journal, which every
proxy opens; a v2 proxy migrates it on open), and keeps a node-signed
`memory_snapshot_delivery` receipt in its `lifecycle.log` before the pod is
handed the directory. The proxy is that copy's only writer: a `Read` binding's
writes stay there, and a `ReadPropose` binding's copy is its branch, which the
tenant root (or the pod holding the binding) publishes onto the space with
`POST /v1/memory/bindings/<id>/publish` and an expected head (compare and swap).
A new run of the same audience is given what was published; a run already bound
keeps its pinned snapshot. Runs of one lineage share the base and never each
other's writes. Stores left at `<memory-root>/<sha256(owner)>/<namespace>` by the
owner-keyed layout become spaces in place under a `TenantAll-legacy` policy at
node start, once, receipted; their writes become private until published.

**Cross-run memory is paused until labels are dependency-stamped** (Program C,
phase C0; lifted per space by C1). A record's label is derived from its
derivation alone, so every root is Public whatever its writer had read: a
session that read Secret data writes Public records, and a view ceiling cannot
withhold what the label does not say. Until a space's records carry their
writer's dependency context, the node refuses, by name
(`CrossRunMemoryUnavailable: record labels are not yet dependency-stamped`):

- creating a `Workspace` or `TenantAll` policy, or a `Lineage` policy over a
  space any of whose policies (live or revoked) admits another lineage;
- minting a binding under such a policy, or one an earlier node recorded, before
  any snapshot is written or receipted;
- admitting a publish from a binding under one.

The one decider is `Registry::cross_run_reach` (`memory_space.rs`). Lineage
audiences keep working: the runs of one lineage share one space. A migrated
owner-keyed store records no lineage that owns it, so it is delivered to **no**
run until C1: its `TenantAll-legacy` policy is still recorded, and its journal is
kept in place, untouched. This pauses the legacy layout's cross-run persistence.
The bind-time `QuotaFullyAllocated` refusal names the policy's own allocation
and no unreserved byte count, which would count bytes the caller cannot see. The
refusal itself is still a one-bit bind-time availability channel (C3 replaces
it). None of this is a confidentiality claim for memory: it withholds a channel
the labels cannot yet decide, and says nothing of timing or of what a
delivered snapshot does once a run holds it.

The local development driver passes explicit proxy arguments and clears ambient
memory environment settings. A mediated container receives a dedicated bind at
`/run/nucleus/memory` and matching proxy environment. The proxy's file lock permits
one active writer per journal, and the node is the only writer of a space's own
journal. An absent selector provisions no persistent memory.
Unmediated containers and VM drivers refuse the selector because no memory
transport has been provisioned for them. A local driver whose proxies run on the bare tier
(a non-root node with `--allow-local-driver`) therefore cannot provision memory:
the proxy refuses the journal at startup. Directory selection does not make the
local driver an isolation boundary.

A live mediated Docker check inside Apple Container verified write → cancellation
→ node restart → replacement pod → recall with the same record and label. Unix
container proxies receive a node-issued pod SVID and use `/workspace` in their
container-local spec. Failed proxy readiness rolls the launch back rather than
returning a pod with no proxy address. This establishes the container storage
lifecycle, not microVM storage or host-authoritative memory admission.
