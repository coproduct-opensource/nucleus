# Kernel-behaviour assumptions at the OS boundary

These named assumptions connect Nucleus decisions to a running Linux/Firecracker
system. They are deployment assumptions, not Lean axioms or conclusions of FM-5.
The trusted host, guest kernel, VMM, and procfs mounts must enforce the behaviours
below. A compromised kernel is outside this claim.

| Name | Assumption and limit | Relying code |
| --- | --- | --- |
| `KB-VSOCK-PEER-CID` | The guest kernel and Firecracker transport report the actual peer CID on accepted AF_VSOCK connections. An unprivileged guest process cannot impersonate host CID 2. This authenticates transport origin, not a particular host user or an uncompromised host. | [`peer_is_host` and the accept path](../../crates/nucleus-tool-proxy/src/pod_mgmt.rs), [`verify_host_vsock`](../../crates/nucleus-tool-proxy/src/auth.rs), [removal of the cmdline HMAC secret](../../crates/nucleus-node/src/firecracker_config.rs) |
| `KB-GUEST-PID-SHARED` | `spawn_admitted` inherits the guest runtime's PID namespace; it does not create a private workload PID namespace. Isolation of runtime secrets relies on the distinct workload uid and Linux procfs/ptrace access checks, not PID invisibility. A host jailer namespace is a separate boundary and does not isolate processes inside the guest. | [`spawn_admitted`](../../crates/nucleus-tool-proxy/src/workload.rs) |
| `KB-PROCFS-STATUS` | The node reads a genuine, trusted host procfs mount, and the numeric child PID still denotes the intended VMM process when checked. `Seccomp` is a kernel-reported snapshot: mode 2 indicates filter mode, not the identity or adequacy of the installed BPF program. Polling does not prove future process state or eliminate PID-reuse races. | [`verify_seccomp_active` / `verify_seccomp_active_within`](../../crates/nucleus-node/src/firecracker_config.rs) |
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
