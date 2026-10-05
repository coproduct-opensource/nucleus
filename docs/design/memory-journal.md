# Runtime memory journal

The tool proxy accepts `--memory-store /private/runtime/project-memory.jsonl`
and `--memory-namespace project-a` (also `NUCLEUS_MEMORY_STORE` and
`NUCLEUS_MEMORY_NAMESPACE`). Both settings are required together. Without them,
memory remains process-local. The operator creates the parent directory with
mode `0700`; the proxy creates the journal with mode `0600`. The path must be
absolute and outside the agent workspace. Existing symlinks and non-regular
files are refused. One proxy holds an exclusive file lock for its lifetime.

The journal begins with a versioned namespace header. Each subsequent line is
one accepted memory record, including its value, label, and derivation. Startup
checks the namespace and replays records in admission order through the same
provenance validator used for new writes. It never deserializes a pretrusted
memory set. Missing parents, unavailable transforms, invalid provenance,
malformed records, and incomplete trailing writes stop startup. The journal
has a 64 MiB limit; capacity exhaustion refuses additional writes.

The live memory-write handler spends its authority and validates a candidate
state, then appends, flushes, and syncs the record before publishing the state or
returning success. A duplicate accepted record does not add another journal line.
Any uncertain write latches the store unavailable for both writes and recalls
until restart; it cannot be hidden by serving a stale in-memory state. Cancellation
during persistence also leaves that latch set. An interrupted caller may have
committed a record, so a retry remains content-addressed and idempotent.

Recall uses the restored record's label through the existing flow-graph path.
The journal does not persist a promoted recall label or turn a saved record into
permission to act. Source assertions retain the existing provenance model;
storage adds no external attestation of their truth.

The operator owns the file and namespace assignment. This is single-proxy durable
storage, not a shared multi-tenant memory service. Firecracker provisioning of storage
across pod lifetimes, host-mediated memory authority, migration/compaction,
automated recovery of incomplete writes, and durable declassification burn
history still need implementation. A disposable guest root filesystem does not
become persistent merely by setting these options.

## Node-managed namespaces

A node may opt in with `--memory-root /private/runtime/memory` (or
`NUCLEUS_NODE_MEMORY_ROOT`). The directory must already exist, be private, and
be separate from the node's configured workspace root. A pod requests a store
with metadata label `nucleus.io/memory-namespace: project-a`; namespace names
contain 1–64 ASCII letters, digits, underscores or hyphens.

After authority admission, the node uses the issued root-owner identity to
select `<memory-root>/<sha256(owner)>/<namespace>/memory.jsonl`. The proxy's
journal header is bound to that owner hash and namespace. A spec cannot supply a
host path or override the owner. New directories are private and their parent
entries are synced. Cancellation stops the pod and retains its memory directory;
replacement pods with the same owner and namespace reopen the journal. Different
owners get different directories even when they choose the same namespace.

The local development driver passes explicit proxy arguments and clears ambient
memory environment settings. A mediated container receives a dedicated bind at
`/run/nucleus/memory` and matching proxy environment. The proxy's file lock permits
one active writer per journal. An absent selector provisions no persistent memory.
Unmediated containers and VM drivers refuse the selector because no memory
transport has been provisioned for them. The local driver retains its documented
unsandboxed-host limitations; directory selection does not make it an isolation
boundary.

A live mediated Docker check inside Apple Container verified write → cancellation
→ node restart → replacement pod → recall with the same record and label. Unix
container proxies receive a node-issued pod SVID and use `/workspace` in their
container-local spec. Failed proxy readiness rolls the launch back rather than
returning a pod with no proxy address. This establishes the container storage
lifecycle, not microVM storage or host-authoritative memory admission.
