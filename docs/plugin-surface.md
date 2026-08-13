# Nucleus plugin surface — pluggable vendor neutrality

**Status:** Living map of the seams that make nucleus vendor-neutral.
**Audience:** integrators, backend authors, architecture review.

Nucleus is a **permission algebra and enforcement kernel** — it does not own the
LLM, the sandbox, the CA, the mesh, or the audit backend. Each of those plugs in
through a typed seam. This page enumerates those seams so an integrator can see
exactly where a vendor slots in, and so no vendor is ever hard-coded in the core
(see `CLAUDE.md` vendor-neutrality rules).

Each axis below is **a trait or enum with ≥1 shipped implementation and room for
more**. Where a seam is a *trust or isolation* boundary, it carries a
**clamp**: the kernel never trusts a backend's self-description upward — a weaker
backend cannot claim a stronger guarantee (e.g. `trust_gate` auto-clamps enforced
isolation ≥ requested; `not_proven` makes over-reading an attestation unsayable).

## The eight axes

### 1. Agent / workload (the thing being governed)
- **Seam:** the pod `workload` + `OVERLAY_DIR` (an opaque agent runtime baked over
  the rootfs; nucleus restores its own mediating binaries if the overlay shadows
  them) + generic `credentials.env` (arbitrary key/value — never a vendor token).
  The vendor-aware *orchestrator* is external and translates its concerns into a
  `PodSpec`.
- **Shipped:** the OpenClaw/NemoClaw demo workload.
- **Pluggable:** **Claude Code, Codex**, Aider, any agent CLI; MCP tool servers via
  `ToolQualityGate` / `mcp_mediation`.
- **Neutrality:** the kernel never names an LLM vendor; credentials are generic env.

### 2. Hardware / attestation root (who is genuine)
- **Seam:** `SvidAttestationBackend` + the `AssuranceLevel` (L0–L3) / `Claim`
  vocabulary, with the closed `not_proven` set (over-reading is *unsayable*).
- **Shipped:** `SelfMeasuredBackend` (software, L1); `TpmDevidBackend` (TPM 2.0
  DevID — residency → EK-manufacturer-root chain → AK↔EK credential-activation
  binding → **L2Device** composition, all pure-Rust, no `libtss2` in the TCB).
- **Pluggable:** **Apple App Attest / Secure Enclave** (an SEP-resident key attested
  by Apple's chain — the AK↔EK dance largely dissolves since the SEP attests its
  own key atomically), cloud instance identity (AWS/Azure/GCP), FIDO/YubiKey.

### 3. Substrate / isolation driver (where the agent runs)
- **Seam:** `enum DriverKind` (node dispatch) + `BackendCapability` (a backend
  *declares* which isolation levels it can enforce; `require_isolation` clamps
  enforced ≥ requested, so a foreign substrate cannot overclaim).
- **Shipped:** `Local`, `Firecracker`, `Container`; capabilities
  `BackendCapability::{FIRECRACKER, APPLE_VZ}` (the Apple-VZ capability is already
  declared and tested).
- **Pluggable:** **Apple Virtualization.framework (native)** — the VZ driver (see
  below); **OpenShell** and other foreign substrates; gVisor; Kata; the Kubernetes
  `agent-sandbox`.

### 4. Identity / CA / trust root (who signs the SVID)
- **Seam:** `CaClient` (SVID issuance), `DidResolver` (DID methods), `WalletMapping`,
  plus SPIFFE federation (consuming foreign trust bundles).
- **Shipped:** `SelfSignedCa`, `SpireCaClient`, `auto_detect_ca`; did:web / caching /
  in-memory resolvers.
- **Pluggable:** **SPIRE, smallstep**, other DID methods, external SPIFFE trust domains.

### 5. Transparency / audit / lineage (proving what happened)
- **Seam:** `TreeWitness` (co-signs Signed Tree Heads over the Merkle lineage),
  `VerdictSink` / `AuditBackend` (where each kernel decision is recorded).
- **Shipped:** `Ed25519Witness` (in-process); `Art12Sink` (EU AI Act Article 12
  hash-chained + HMAC record-keeping); S3 audit sink.
- **Pluggable:** **external witnesses** (Rekor / Sigsum / C2SP `tlog-witness`) that
  lift trust off the operator to a witness quorum; SIEM sinks.

### 6. Transport / discovery / mesh (where the seam lives on the wire)
- **Seam:** transport kind (`http` | `mcp`), vsock (guest↔host), iroh
  (dial-by-`EndpointID`, Pkarr/DNS discovery).
- **Shipped:** vsock workload API, HTTP/MCP, iroh (the "call SPIFFE agents anywhere"
  spike).
- **Pluggable:** **Tailscale** and other overlay meshes; relay/discovery providers.

### 7. Policy / mediation (what is allowed)
- **Seam:** `PolicyCheck`, `ToolCallGuard` / `PermissionGuard`, `ToolQualityGate`,
  the Cedar bridge (`cedar_bridge`).
- **Shipped:** the native permission lattice + Cedar bridge.
- **Pluggable:** Cedar / OPA-style external policy; custom tool-quality gates.

### 8. Observability / reputation
- **Seam:** `ReputationMetrics` / `MetricsCollector`.
- **Shipped:** in-process metrics.
- **Pluggable:** Prometheus / OTel exporters; reputation backends.

## How the axes compose — the mediation receipt
The agent↔tool boundary is where axes 2, 5, and 7 must bind into one verifiable
claim. A **`MediationReceipt`** (`portcullis::mediation_receipt`) is signed by the
mediator over *who mediated* (its SPIFFE id — axis 4), *what it decided* (axis 7),
and the *hash of the Article 12 record* that recorded it (axis 5). A relying party
then verifies: (1) the signature; (2) that the mediator's SVID is **attested**
(axis 2); (3) that the record hash is **included in the witnessed lineage** (axis
5). So one tool crossing becomes third-party-verifiable regardless of which vendor
fills each axis.

## Apple Silicon and the VZ driver (axis 3, in progress)
Apple Virtualization.framework is the macOS-native isolation substrate. The VZ
substrate is additive behind two existing seams, and **the enforcement half is
already wired**: `BackendCapability::APPLE_VZ` is defined and tested in
`portcullis::enforcement`, and `trust_gate::isolation_backend()` already selects
it when the node runs the `apple-vz` backend (so `require_isolation` clamps a
VZ pod's enforced isolation exactly as it does a Firecracker pod's). Its
attested-mediator key comes from axis 2's Apple/SEP backend.

**What remains is the node *driver*** — a `DriverKind::AppleVz` + a `spawn_vz_pod`
that boots a `VZVirtualMachine`, carries the workload API over VZ's virtio-socket
(in place of Firecracker's vsock/jailer, whose assumptions do not port), and
sources the mediator key from the Secure Enclave. It is macOS-only, so it is not
exercised on the Linux CI / Lima path. The concrete first brick is to **extract
the driver dispatch out of `main.rs` into a `driver` module** (the line ratchet
mandates paying for additions by extraction) and add the `AppleVz` arm there.
