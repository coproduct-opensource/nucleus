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
storage, not a shared multi-tenant memory service. Node provisioning of storage
across pod lifetimes, host-mediated memory authority, migration/compaction,
automated recovery of incomplete writes, and durable declassification burn
history still need implementation. A disposable guest root filesystem does not
become persistent merely by setting these options.
