# State of the Art (2025–2026): Isolation and Attestation for Untrusted Agent Workloads

*Research memo for the Nucleus North Star ("structurally incapable of exceeding authorization"). Static web research, 2026-09-08. Where a primary source was unreachable from this sandbox (arxiv.org, lwn.net, ietf.org, wasi.dev were egress-blocked) the claim is drawn from the abstract/secondary coverage and marked (sec.).*

## 1. Framing: what "structurally incapable" requires

Clause (4) of the North Star decomposes into four properties that the 2026 literature and industry practice now treat separately:

1. **Kernel/hypervisor escape resistance** – the agent's code cannot reach the host. This is the microVM/gVisor/CHERI question.
2. **Effect mediation** – every side effect (file write, network byte, process spawn, GPU op) crosses a boundary where policy is evaluated. This is the Landlock/seccomp-notify/FUSE/egress-proxy question.
3. **Secret confinement** – credentials and data the principal did not authorize the agent to see are unreachable even if (1) partially fails. This is the confidential-computing / secret-hiding / credential-broker question.
4. **Verifiable posture** – a relying party can check, cryptographically, that (1)–(3) were actually in force for a given run. This is the attestation/RATS/WIMSE question.

The main 2026 shift is that (2) and (4) have matured from research into shipped primitives, while (1) has consolidated around Firecracker-class microVMs with gVisor as the accepted "cloud-scale" alternative.

## 2. Execution isolation

### Firecracker (v1.13–v1.17, 2025–2026)
The CHANGELOG (fetched) shows the relevant trajectory: PCI support went GA in v1.13 and became the basis for VFIO device passthrough; v1.14 added virtio-pmem and virtio-mem memory hotplug; v1.15 added VMClock, custom CPU templates, and diff snapshots without dirty-page tracking (`mincore`); v1.16 added developer-preview PCI virtio hot(un)plug and Linux 6.18 host support; v1.17 added virtio device reset, `MADV_HUGEPAGE`, and Graviton5. Snapshot restore for warm sandboxes is in the 5–30 ms range per provider blogs, with restore-time fixes landing throughout 2026. The design doc (fetched) is explicit about the model: every vCPU thread is treated as malicious from the moment it starts; containment is jailer (chroot/cgroups/namespaces, privilege drop) plus per-thread seccomp installed before guest code runs, with a minimal device model (virtio net/block, serial, partial i8042, KVM-provided PIC/IOAPIC/PIT). Crucially, "Firecracker does not perform any network traffic filtering... all egress traffic from a guest is considered untrusted and should be filtered at the host level" – i.e. effect mediation is explicitly out of scope of the VMM and must be built around it.

Two 2026 CVEs are relevant to TCB accounting: CVE-2026-1386 (jailer symlink host-file overwrite during initialization copy) and CVE-2026-5747 (OOB write in the virtio-PCI transport, 1.13.0–1.14.3 and 1.15.0, guest-root to VMM crash or host code execution). Both are in the *host-side* Rust VMM/jailer, not in KVM, and both landed in newly added surface (PCI transport, jailer setup) – a reminder that enabling PCI/GPU passthrough grows the TCB.

**Secret hiding / secret freedom.** A `feature/secret-hiding` branch exists in the Firecracker repo; the design (from LWN coverage of `guest_memfd` mmap, sec.) is to back guest memory with `guest_memfd` and remove it from the host kernel direct map so host-kernel transient-execution attacks cannot read guest memory. Kata 3.32 (June 2026, fetched) already consumes KVM-managed `guest_memfd` for confidential workloads. This is the cheapest available upgrade in "secret confinement" that does not require a TEE.

### gVisor
Platform docs (fetched): the Sentry intercepts syscalls via `systrap` (seccomp `SECCOMP_RET_TRAP` + SIGSYS, default since mid-2023) or the KVM platform on bare metal; ptrace is deprecated. Directfs narrows the Sentry's host filesystem view; `nvproxy` forwards NVIDIA ioctls for GPU workloads. Adoption: Modal, Google's Kubernetes SIG **Agent Sandbox** (v1beta1 CRDs `Sandbox`, `SandboxTemplate`, `SandboxClaim`, `SandboxWarmPool`; delegates isolation to gVisor or Kata via `RuntimeClass`, default-deny NetworkPolicy), and Anthropic's hosted code execution (sec.). Trade-off stated consistently across sources: ~0% overhead for CPU-bound work, 2–200x for file-I/O-heavy work; the boundary is a ~memory-safe Go kernel plus a tight host seccomp filter rather than a hardware VM boundary.

### Kata Containers 4.x
4.0.0 (2026-07-20, fetched release page) made the Rust `runtime-rs` the default, added Dragonball (in-process Rust VMM), unified block-device storage, virtio-mem hotplug, VFIO cold-plug, EROFS + dm-verity rootfs integrity, and GPU support across hypervisors; 4.1.0 (2026-08-21) added OpenVMM. Kata remains the substrate for Confidential Containers (CoCo) and is a first-class Agent Sandbox runtime. The Go runtime is deprecated (CVE fixes only).

### Unprivileged Linux primitives: Landlock + seccomp-notify
Landlock ABI progression (kernel docs, sec.): v4 (6.7) TCP bind/connect port rules; v6 (6.12) IPC scoping for abstract UNIX sockets and signals; v7 (6.15) audit-logging control; **6.19** adds `LANDLOCK_SCOPE_PATHNAME_UNIX_SOCKET`. **Sandlock** (DSN 2026; README fetched) is the clearest 2026 articulation of the "split TCB" pattern: static, input-independent policy compiled into kernel-enforced Landlock + deny-only seccomp-bpf, with a narrow async supervisor receiving `seccomp` user notifications for runtime-dependent decisions (network CIDR/denylist logic, HTTP method+host+path ACLs behind a transparent TLS-terminating proxy with ephemeral CA, credential injection post-ACL, TOCTOU-safe `execve` inspection by freezing the task, COW/dry-run filesystem). `pidfd_getfd` and `SECCOMP_IOCTL_NOTIF_ADDFD` let the supervisor perform the privileged operation and hand back an fd. Requires 6.12+ for the full set; overhead ~5 ms startup, ~97% of bare-metal Redis throughput. Limitations they document are the ones Nucleus should care about: Landlock cannot express "all ports" without enumeration; path-based decisions must stay static (no path strings in the supervisor callback) to avoid TOCTOU; kernel objects (FIFOs, sockets, devices) are never reverted.

Anthropic's `sandbox-runtime` (README fetched) and OpenAI Codex use the same family on developer machines: bubblewrap + seccomp on Linux (network namespace removed; only Unix-socket proxies), Seatbelt on macOS, a dedicated SID + WFP egress fence on Windows. Its README is candid: the proxy "does not otherwise inspect the traffic," domain fronting through broad allowlists is an exfil path, inherited Unix-socket fds are not blocked by seccomp, and the whole thing targets "accidental or naive unauthorized access," not determined adversaries.

### WebAssembly Component Model / WASI 0.3
WASI 0.3.0 shipped 2026-06-11 (sec.), moving async (`stream<T>`, `future<T>`) into the Component Model and dropping `wasi:io`; coverage runs on Wasmtime and jco. The security story is unchanged and remains the purest capability model available: a component has no ambient authority, receives only the handles passed in, cannot open sockets or paths not granted. In 2026 practice Wasm is used for *tool* and *policy-plugin* isolation (deterministic, small, easily attested by hash) rather than for the agent's general shell, because POSIX-shaped agent workloads (git, compilers, package managers) do not fit.

### CHERI
CHERI/Morello and CHERIoT remain research/embedded (CHERI Blossoms 2026; CHERIoT RTOS compartments). No 2026 cloud sandbox provider ships CHERI. Relevant only as a long-horizon way to make the *supervisor itself* compartmentalized; not a 2026 building block.

## 3. Confidential computing and attestation

AMD SEV-SNP and Intel TDX are the deployed CPU TEEs; ARM CCA (RME, Armv9.2+/9.3-A; Realms attested via RSI) has upstream Linux KVM support but little production availability as of 2026. NVIDIA CC mode on H100/H200/B200/GB200 encrypts PCIe (and NVLink on Blackwell) traffic and exposes GPU attestation; the CPU TEE (TDX/SNP) anchors the GPU measurement, and multi-tenant reuse requires PF-FLR memory scrubbing. Kata 3.32+ boots TDX guests; CoCo **Trustee** (repo fetched) provides the RATS roles as services: KBS = Relying Party, Attestation Service = Verifier (evidence from TDX, SGX, SEV-SNP, ARM CCA, Hygon CSV), RVPS = reference-value/endorser, with secret release gated by policy over verified claims.

The identity layer is converging on IETF WIMSE: `draft-liu-wimse-wit-attestation` carries attestation evidence inside a Workload Identity Token bound with DPoP so it survives TLS-terminating proxies; `draft-reddy-wimse-workload-attestation` describes TEE-workload-to-verifier flows; `draft-winmagic-wimse-condition-bounded-credentials` proposes non-exfiltratable keys valid only by presence (sec.). The pattern relevant to Nucleus's existing SPIFFE/`nucleus-spiffe-hail` work: SVID issuance conditioned on verified attestation claims, then agent-level delegation (AIP-style, sec.) chained off that identity.

## 4. Effect mediation: network, filesystem, browser, GPU

**Network.** The 2026 consensus (Sandlock, sandbox-runtime, Azure Container App Sandboxes + Agent Governance Toolkit, NVIDIA OpenShell, Vercel's egress firewall on all plans as of 2026-08-05, Blaxel, AWS) is: remove the network namespace or nftables-redirect all TCP to a per-sandbox proxy; deny by default; classify TLS vs plain; TLS-terminate with an ephemeral CA when method/path/header policy is required; inject credentials at the proxy so secrets never enter the sandbox. Two documented gaps: (a) **DNS** – HTTP allowlists with an open resolver leak metadata and enable tunneling; the fix is an allowlist-aware forwarder inside the sandbox netns (openai/codex #22387, Route 53 DNS Firewall pattern); (b) **domain fronting / broad allowlists** (e.g. `github.com`) – acknowledged unsolved in sandbox-runtime; only content-aware proxies or narrow path ACLs close it.

**Filesystem.** Two schools. Bind-mount scoping (bwrap, Landlock paths, Directfs) is kernel-enforced, zero-overhead, static, and TOCTOU-safe but coarse. FUSE mediation (AgentFS: SQLite-backed COW overlay bind-mounted over the workdir; "Don't Let AI Agents YOLO Your Files," sec.) gives per-op policy, reversibility, and provenance at the cost of a userspace server in the path and a larger TCB. Sandlock's answer – static Landlock for authority, supervisor COW only for *reversibility* – is the sensible synthesis.

**Browser.** Chromium site isolation protects users from sites, not principals from agents. 2026 practice is remote browser isolation: a disposable Chromium in its own microVM/container (Firecrawl Browser Sandbox, OpenClaw Docker backend) returning screenshots/DOM; the agent never holds the browser's cookies or network. Browser egress must go through the same proxy as the shell.

**GPU.** Options ranked by boundary strength: (i) VFIO passthrough to a microVM (Firecracker PCI, Kata VFIO cold-plug) – hardware boundary, full device to one tenant; (ii) gVisor `nvproxy` – ioctl-level proxying, shared driver; (iii) CC-mode GPU with attestation – confidentiality against the host. No provider offers fine-grained *authorization* of GPU effects; GPU is all-or-nothing.

## 5. How providers draw the boundary (2026)

| Provider | Boundary | Notes |
|---|---|---|
| E2B, Vercel Sandbox, Fly Machines | Firecracker microVM | E2B no GPU; Fly is a raw primitive |
| Modal | gVisor | GPU (H100/A100) via nvproxy-style path |
| Daytona | OCI container by default, optional Kata | ~27–90 ms cold start via warm pools |
| Cloudflare Sandboxes | Cloudflare Containers (shared kernel) | container-tier isolation |
| Google Agent Sandbox / GKE Sandbox | gVisor (Kata optional), default-deny NetworkPolicy | K8s SIG, v1beta1 |
| OpenAI Codex cloud | microVM, offline by default after setup phase | two-phase network model |
| Anthropic hosted execution | gVisor container per session (sec.); local: bwrap/Seatbelt/WFP | sandbox-runtime open-sourced |
| Azure ACA Sandboxes | Hyper-V isolated containers + egress allowlist fail-closed | Agent Governance Toolkit |

The pattern: the *escape* boundary is a commodity (microVM or gVisor), and vendors differentiate on the *mediation* layer (egress policy, credential injection, snapshots). None of them attest the mediation layer to the principal.

## 6. Conclusion: smallest credible TCB for "cannot exceed authorization" in 2026

**Trusted (must be correct):**
1. **Hardware + KVM** (or a TEE's RMM/PSP/TDX module). Unavoidable; mitigated by CPU-vendor attestation.
2. **A minimal Rust VMM in a jailer** – Firecracker-class, PCI *off* unless GPU is required, seccomp per thread, `guest_memfd`/secret-hiding where the host kernel allows. Roughly tens of KLoC of Rust, Kani-harnessed in CI. Everything inside the guest (kernel, agent, tools) is untrusted.
3. **A host-side effect supervisor** with the Sandlock split: static kernel policy (Landlock 6.12+/nftables/netns) carries the *authority*; a narrow supervisor (egress proxy with TLS termination + DNS forwarder, credential broker, fd-passing via seccomp-notify or vsock) carries the *decisions*. This is where Nucleus's policy lattice, budgets, time bounds, and revocation live, and it is the only component whose logic must be *proved* to implement the principal's authorization – hence the Lean/Kani investment belongs here, not in the VMM.
4. **The attestation verifier and policy** (Trustee-style AS + RVPS) *if* run by the principal or a neutral party.

**Attested rather than trusted (verified per run, not assumed):**
- CPU/GPU firmware and the guest measurement (SNP/TDX/CCA evidence, NVIDIA GPU evidence) – via RATS.
- The VMM binary, guest kernel, rootfs (dm-verity/EROFS hash), and the *supervisor's policy blob* – bind their hashes into the attestation report or into a WIMSE WIT with DPoP so the relying party learns which authorization envelope was enforced.
- Wasm tool/policy components – content-addressed, hash-bound.
- The agent model and vendor – never trusted; only its *effects* are, through the supervisor (clause 1 of the North Star follows for free).

**What cannot yet be attested and must be designed around:** DNS/side-channel exfil within an allowed domain, domain fronting behind broad allowlists, inherited fds and Unix-socket authority, GPU-effect granularity, and the gap between "the sandbox had policy P" and "P was the principal's intent" – the last is a receipt/provenance problem, which is where Nucleus's signed receipts and `gatehouse`'s proof-carrying pipelines should attach to the attestation chain.

## Sources
- https://github.com/firecracker-microvm/firecracker/blob/main/CHANGELOG.md
- https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md
- https://github.com/firecracker-microvm/firecracker/tree/feature/secret-hiding
- https://github.com/firecracker-microvm/firecracker/discussions/4845
- https://lwn.net/Articles/1031923/
- https://aws.amazon.com/security/security-bulletins/2026-003-AWS
- https://www.sentinelone.com/vulnerability-database/cve-2026-1386/
- https://emirb.github.io/blog/microvm-2026/
- https://github.com/google/gvisor/blob/master/g3doc/architecture_guide/platforms.md
- https://gvisor.dev/docs/user_guide/gpu/
- https://opensource.googleblog.com/2023/06/optimizing-gvisor-filesystems-with-directfs.html
- https://github.com/kubernetes-sigs/agent-sandbox
- https://agent-sandbox.sigs.k8s.io/docs/use-cases/gvisor-isolation/
- https://cloud.google.com/blog/products/containers-kubernetes/bringing-you-agent-sandbox-on-gke-and-agent-substrate
- https://github.com/kata-containers/kata-containers/releases
- https://www.hpcwire.com/aiwire/2026/07/22/openinfras-kata-containers-4-0-brings-rust-runtime-to-ai-agent-sandboxing/
- https://docs.kernel.org/userspace-api/landlock.html
- https://lwn.net/Articles/1052264/
- https://lwn.net/Articles/1021648/
- https://www.man7.org/linux/man-pages/man2/seccomp_unotify.2.html
- https://github.com/multikernel/sandlock
- https://arxiv.org/abs/2605.26298
- https://arxiv.org/abs/2606.22504
- https://arxiv.org/pdf/2604.13536
- https://turso.tech/blog/agentfs-fuse
- https://github.com/anthropic-experimental/sandbox-runtime
- https://code.claude.com/docs/en/sandbox-environments
- https://openai.com/index/building-codex-windows-sandbox/
- https://developers.openai.com/codex/agent-approvals-security
- https://github.com/openai/codex/issues/22387
- https://wasi.dev/releases/wasi-p3
- https://cheri-alliance.org/events/cheri-blossoms-conference-2026/
- https://cheriot.org/cheri/history/2025/05/16/last-ten-years.html
- https://github.com/confidential-containers/trustee
- https://www.redhat.com/en/blog/introducing-confidential-containers-trustee-attestation-services-solution-overview-and-use-cases
- https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf
- https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html
- https://docs.kernel.org/arch/arm64/arm-cca.html
- https://learn.arm.com/learning-paths/servers-and-cloud-computing/cca-essentials/
- https://www.ietf.org/archive/id/draft-liu-wimse-wit-attestation-00.html
- https://datatracker.ietf.org/doc/draft-reddy-wimse-workload-attestation/
- https://www.ietf.org/archive/id/draft-winmagic-wimse-condition-bounded-credentials-00.html
- https://techcommunity.microsoft.com/blog/linuxandopensourceblog/govern-ai-agents-using-agent-governance-toolkit-and-azure-container-app-sandboxe/4526011
- https://medium.com/@dnotitia/how-nvidia-openshell-sandboxes-ai-agents-intelligent-policy-control-part-3-47927753d39f
- https://aws.amazon.com/blogs/machine-learning/control-which-domains-your-ai-agents-can-access/
- https://blaxel.ai/blog/sandbox-egress-control-outbound-allow-listing
- https://www.firecrawl.dev/blog/introducing-browser-sandbox
- https://blaxel.ai/blog/browser-sandboxing-for-coding-agents
- https://northflank.com/blog/how-to-sandbox-ai-agents
- https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/
- https://blog.logrocket.com/comparing-ai-agent-sandbox-platforms-e2b-modal-daytona-and-more/
- https://modal.com/resources/best-microvm-sandboxes-ai-code-execution
- https://model-checking.github.io/kani/
- https://edera.dev/use-case/ai-agent-sandboxing
