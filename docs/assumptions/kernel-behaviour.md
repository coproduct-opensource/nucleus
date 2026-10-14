# Kernel-behaviour assumptions at the OS boundary

These named assumptions connect Nucleus decisions to a running Linux/Firecracker
system. They are deployment assumptions, not Lean axioms or conclusions of FM-5.
The trusted host, guest kernel, VMM, and procfs mounts must enforce the behaviours
below. A compromised kernel is outside this claim.

| Name | Assumption and limit | Relying code |
| --- | --- | --- |
| `KB-VSOCK-PEER-CID` | The guest kernel and Firecracker transport report the actual peer CID on accepted AF_VSOCK connections. An unprivileged guest process cannot impersonate host CID 2. This authenticates transport origin, not a particular host user or an uncompromised host. | [`peer_is_host` and the accept path](../../crates/nucleus-tool-proxy/src/pod_mgmt.rs), [`verify_host_vsock`](../../crates/nucleus-tool-proxy/src/auth.rs), [removal of the cmdline HMAC secret](../../crates/nucleus-node/src/firecracker_config.rs) |
| `KB-GUEST-WORKLOAD-PIDNS` | In a guest (`ContainmentMode::MicroVM`), `spawn_admitted` starts the workload in a new PID namespace and a private mount namespace (#3344). Its parent is that namespace's init, a fork of the runtime that never execs. The init reaps every orphan and dies with the runtime's handle on the workload. A fresh `/proc` is mounted there with `hidepid=invisible`. The guest kernel must enforce PID-namespace visibility: no pid the workload can name, signal or open under `/proc` denotes a process outside the namespace. If the namespace cannot be made, the workload is refused, never run without it. This is defence in depth under ADR 0013. A guest root can leave the namespace, so the host relies on none of it. The workload's uid and the procfs/ptrace access checks still hold behind it. A host tier's workload still shares the runtime's PID namespace, and its receipt says `pids=shared`. A host jailer namespace is a separate boundary and does not isolate processes inside the guest. Supersedes `KB-GUEST-PID-SHARED`, which FM-5's not-claimed list still names. | [`spawn_admitted`](../../crates/nucleus-tool-proxy/src/workload.rs), [`hardening/pidns.rs`](../../crates/nucleus/src/hardening/pidns.rs) |
| `KB-PROCFS-STATUS` | The node reads a genuine, trusted host procfs mount, and the numeric VMM PID still denotes the intended VMM process when checked. Under the jailer that PID is read from the jail's pid file (`--new-pid-ns`). A pidfd opened at handoff confirms that the process is its pid namespace's init and carries the jail's `--id`, and it performs every kill and wait. `/proc/<pid>` reads made afterwards, by the seccomp poll and `nsenter`, are still path-based. `Seccomp` is a kernel-reported snapshot: mode 2 indicates filter mode, not the identity or adequacy of the installed BPF program. Polling does not prove future process state or eliminate PID-reuse races. | [`verify_seccomp_active` / `verify_seccomp_active_within`](../../crates/nucleus-node/src/firecracker_config.rs), [`vmm_process`](../../crates/nucleus-node/src/vmm_process.rs) |
| `KB-LINUX-CHILD-ISOLATION` | Linux implements the requested uid/gid and supplementary-group changes, no-new-privileges, rlimits, and close-on-exec descriptor closure. Procfs and filesystem access checks enforce the resulting uid boundary. The workload must not acquire privileges that defeat it. | [`spawn_admitted` and its pre-exec hook](../../crates/nucleus-tool-proxy/src/workload.rs) |

FM-5 proves properties of the extracted delivery relation. Its
[not-claimed list](../../crates/portcullis-core/lean/IdentityMaterialNoninterferenceExtracted.lean)
references these names. Binding tests and VM probes provide evidence about particular
builds; they do not prove these kernel assumptions for every deployment.

## Audit boundary

These names are a documentation registry only. No Lean `axiom` declaration or
`.axiom-audit-exceptions` entry is introduced for them. The proven-tier audit must
continue rejecting arbitrary axioms. If an OS-boundary model later represents an
assumption formally, it must identify the corresponding `KB-*` name and keep any
exception confined to that model's audit; it must not enter a proven-tier allowlist.
