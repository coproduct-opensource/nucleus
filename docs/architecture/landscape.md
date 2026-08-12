# Landscape and Rationale

Why Nucleus is built the way it is, stated against what else exists as of July 2026.

This page names specific products and vendors. That is deliberate and is the one
documented exception to the vendor-neutrality rule in `CLAUDE.md`: a competitive
landscape cannot be written without naming competitors. The rule exists to keep
vendor coupling out of *code and interfaces* — nothing on this page is coupling.
The CI gate (`ci/no-vendor-strings.sh`) scans only `nucleus-oidc-core` and
`nucleus-oidc-provider`, so this file is outside its scan paths by construction.

## The stack, layer by layer

Isolation for agent workloads is not one market. It is eight, and almost every
project in the space picks exactly one.

### L0 — Same-kernel process sandboxes

macOS Seatbelt, Linux Landlock, seccomp-BPF, bubblewrap. This is what nearly
every coding-agent CLI ships today: Seatbelt on macOS, Landlock + seccomp or
bubblewrap on Linux, usually paired with an egress proxy.

Cheap, unprivileged, no daemon. Also escapable — a working escape from a
production agent's bubblewrap sandbox was published in April 2026. The guest and
the host share a kernel, so a single kernel bug is a full compromise.

**Where Nucleus sits:** this is Tier 1 (`nucleus run --local`). We ship it because
the alternative is that people run agents with no boundary at all, and
[production-delta.md](../production-delta.md) records that its isolation is
weaker than Tier 2. We do not claim it is a security boundary against a
determined attacker.

### L1 — Userspace kernels

gVisor intercepts syscalls in userspace and reimplements them. Container-speed
cold start with a much smaller host kernel attack surface. The cost is
permanent: roughly 274 of ~350 syscalls are implemented (~78%), so there is both
a compatibility gap and a reimplementation surface of its own. Modal is the
best-known adopter.

**Where Nucleus sits:** we skipped this rung. A partial syscall surface is a
partial boundary, and our proof obligations are stated over a boundary we can
enumerate completely.

### L2 — Hypervisor isolation

Firecracker with its jailer, Kata Containers (Dragonball VMM), Cloud Hypervisor,
Edera (a container-native Type-1 hypervisor derived from Xen, written in MISRA
C), Apple's `container` (one lightweight VM per container on
Virtualization.framework), and Microsoft Hyperlight (a micro-VM with *no guest
kernel at all* — 1–2 ms starts, stateless per-invocation).

**This layer became the consensus in 2026.** Apple shipped `container` 1.0 in
June 2026 on a one-VM-per-container model. Vercel Sandbox went GA on Firecracker
in January 2026. The published commentary is uniform that shared-kernel
container isolation is no longer acceptable for untrusted agent code.

**Where Nucleus sits:** this is Tier 2 (`nucleus run --vm`), Firecracker under
the jailer. See [Rationale](#rationale) for why we do not claim differentiation
here, and what we do claim instead.

### L3 — Managed sandbox platforms

E2B (Firecracker), Modal (gVisor), Daytona (hardened OCI containers, 27–90 ms
provisioning), Vercel Sandbox (Firecracker, dedicated kernel and netns per
sandbox), Cloudflare, Fly Machines, Blaxel (~25 ms). Above them, the hyperscaler
runtimes: Bedrock AgentCore (GA, eight-hour sessions), Vertex AI Agent Engine,
Azure AI Foundry Agent Service.

These win decisively on time-to-first-run. They are also, without exception,
lock-in — the hyperscaler runtimes are per-cloud by construction.

A note that matters for our thesis: Unit 42 published a **bypass of AgentCore's
network-isolation mode**. A hyperscaler's tested isolation control was bypassed.

### L4 — Policy gateways

MCP gateways with declarative policy decision points — ToolHive, IBM
ContextForge, agentgateway, Lunar, Cerbos, Permit.io — evaluating Cedar, Rego,
or YAML rules before every tool invocation. AWS put Cedar directly into
AgentCore Policy. Enforcement depth varies widely across implementations, from
server-level down to individual parameter values.

**Where Nucleus sits:** `nucleus-policy-kernel`, `nucleus-policy-cert`,
`nucleus-mcp-guard`, `nucleus-tool-proxy`. The difference is not the policy
language; it is that our decision function is the same one the proofs are stated
over, and it is the same one enforced at Tier 1 and Tier 2.

### L5 — Information-flow control

CaMeL, FIDES, Progent, RTBAS, FORGE. The field converged on a single strategy:
enforce security *outside* the model with a deterministic policy that mediates
actions, rather than training the model to refuse. CaMeL attaches capability
metadata to every value and gates sinks on the provenance of the data reaching
them.

The measured cost is the important number: CaMeL solves 77% of AgentDojo tasks
against 84% for an undefended baseline — seven points of utility for provable
guarantees. That is the price of this layer, and it is cheaper than most people
assume.

**Where Nucleus sits:** `nucleus-ifc`, `nucleus-ifc-kernel`, and the exposure
lattice in NORTH_STAR Pillar A. Same idea, arrived at independently, with the
lattice algebra machine-checked rather than argued.

### L6 — Identity

SPIFFE/SPIRE is the settled answer for non-human identity: short-lived SVIDs,
automatic rotation, trust-bundle federation across trust domains, no long-lived
API keys to leak. Adoption is broad — Istio, App Mesh, Tetragon, commercial
SPIRE distributions.

**Where Nucleus sits:** `nucleus-identity`, `nucleus-oidc-core`,
`nucleus-oidc-provider`, `nucleus-trust-registry`. Standards-track, not novel,
and deliberately so.

### L7 — Provenance and attestation

SLSA for the maturity model and provenance predicate, in-toto for the
attestation format, DSSE for the envelope, Sigstore/Rekor for keyless signing
tied to OIDC identity. Newer agent-specific work proposes an "Action Attestation
Layer" that emits a signed receipt per tool call into an append-only provenance
log.

**Where Nucleus sits:** `nucleus-receipt`, `nucleus-provenance`,
`nucleus-lineage`, `nucleus-witness`, `nucleus-audit`, `nucleus-bundle-cas`.
The append-only property is currently *tested*, not proved — see
[production-delta.md](../production-delta.md), issue #427.

### L8 — Formal methods

All of it is 2026, and nearly all of it is research-stage: Lean4Agent for
workflow and trajectory verification; "Type-Checked Compliance" applying Lean 4
guardrails to financial agents; a three-layer method for mechanically checkable
capability-containment proofs; and the Sovereign Execution Broker, which argues
for certificate-bound *preventive* authority in preference to documentary
receipts.

That last one is essentially `nucleus-policy-cert`, derived independently by
someone else. We take that as confirmation rather than competition.

## Rationale

**The claim: every other project picks one layer. Nucleus composes L0–L8 behind a
single enforcement boundary, and proves the boundary rather than testing it.**

That is not a marketing frame; it is the crate list. L2 is `nucleus-node`, L4 is
`nucleus-policy-kernel` and friends, L5 is `nucleus-ifc`, L6 is
`nucleus-identity`, L7 is `nucleus-receipt`, and L8 is the Lean theorems and Kani
harnesses wired as required merge checks and enumerated in
[Verified Claims](../verified-claims.md). It is also exactly the design
choice recorded in NORTH_STAR Pillar A: *prove properties about the enforcement
boundary, not about agent behavior.*

### The two findings that carry the argument

Two 2026 results are the strongest external evidence for the thesis, and neither
is ours:

1. A production agent escaped its own bubblewrap sandbox (April 2026).
2. Unit 42 bypassed AgentCore's network-isolation mode.

In both cases the enforcement had been *tested* and was believed to hold. Tests
sample a state space; they do not close it. That is the entire argument for
mechanized proof over an enumerable boundary, made by third parties.

### Where we are genuinely alone

**Proof-carrying enforcement in a shipping runtime.** L8 exists as papers and one
financial-guardrails prototype. We are not aware of another production isolation
path with Lean and Kani as required CI merge gates.

**The economic layer.** `nucleus-permission-market`, `nucleus-externality`,
`nucleus-creditworthiness`, `nucleus-econ-kernels` have no counterpart anywhere
in the landscape. The 2026 agent-economics literature is market-design theory
about agents transacting; none of it is runtime enforcement of what an agent may
spend its authority on.

**Vendor neutrality.** Every L3 platform is lock-in and every hyperscaler runtime
is per-cloud. Nucleus is MIT, self-hostable, and takes credentials as opaque
key-value pairs.

### Where we are not differentiated, and should not claim to be

Stating these plainly is what makes the claims above credible.

**L2 is commodity.** Firecracker under the jailer is table stakes in 2026 —
E2B and Vercel Sandbox do the same thing. Our claim at this layer is
*correctness*, not novelty. Specifically: cgroup limits are applied before
`exec` rather than after (`firecracker_config.rs` — the ordering property is why
the jailer is worth adopting at all); seccomp is verified active after launch and
fails closed rather than being assumed; netns assignment is drift-checked. Most
jailer adopters run it without verifying that it took.

**Cold start.** Hyperlight starts in 1–2 ms and Blaxel provisions in ~25 ms
against Firecracker's ~150 ms boot. We should never compete on this axis. The
honest statement is that we spend that time buying a full kernel, a real
filesystem, and a process model — which a stateless per-invocation micro-VM does
not give you, and which agent workloads need.

**Ergonomics.** Managed platforms win on time-to-first-run and will keep
winning. Tier 0 (`nucleus audit`, `pip install`) is the counter, and per
NORTH_STAR Pillar C it is the pillar most at risk. A runtime nobody adopts
proves nothing.

## Reading list

Isolation layer:

- [Your Container Is Not a Sandbox: The State of MicroVM Isolation in 2026](https://emirb.github.io/blog/microvm-2026/)
- [Kata vs Firecracker vs gVisor: container isolation compared](https://edera.dev/stories/kata-vs-firecracker-vs-gvisor-isolation-compared)
- [Hyperlight](https://hyperlight.org/) and [Firecracker vs Hyperlight](https://www.pandastack.ai/blog/firecracker-vs-microsoft-hyperlight/)
- [apple/container technical overview](https://github.com/apple/container/blob/main/docs/technical-overview.md)

Platform layer:

- [AI agent sandboxing in 2026: primitives, runtimes, platforms](https://manveerc.substack.com/p/ai-agent-sandboxing-guide)
- [Where should your AI agent run code](https://www.developersdigest.tech/blog/ai-agent-code-sandbox-comparison-2026)

Failures of tested enforcement:

- [Cracks in the Bedrock: escaping the AWS AgentCore sandbox](https://unit42.paloaltonetworks.com/bypass-of-aws-sandbox-network-isolation-mode/)
- [What the bubblewrap sandbox escape tells us about agent runtime hardening](https://tanayshah.dev/blog/agent-sandbox-runtime-hardening/)
- [List of coding agent sandboxes, 2026-05](https://gist.github.com/wincent/2752d8d97727577050c043e4ff9e386e)

Policy, IFC, identity, provenance:

- [Best open source MCP gateways in 2026](https://www.lunar.dev/post/the-best-open-source-mcp-gateways-in-2026)
- [Least-privilege authorization in multi-agent chains using Cedar](https://aws.amazon.com/blogs/security/enforce-least-privilege-authorization-in-multi-agent-ai-chains-using-cedar/)
- [Defeating Prompt Injections by Design (CaMeL)](https://floriantramer.com/publications/camel25/)
- [Indirect prompt injection: attacks, defenses, and the 2026 state of the art](https://zylos.ai/research/2026-04-12-indirect-prompt-injection-defenses-agents-untrusted-content/)
- [SPIFFE: securing the identity of agentic AI and non-human actors](https://www.hashicorp.com/en/blog/spiffe-securing-the-identity-of-agentic-ai-and-non-human-actors)
- [SLSA v1.1 provenance and in-toto attestations](https://slsa.dev/spec/v1.1/faq)
- [Verifiability-First Agents](https://arxiv.org/pdf/2512.17259)

Formal methods for agent runtimes:

- [Methods for formal verification of agent skills: capability-containment proofs](https://arxiv.org/pdf/2605.23951)
- [Sovereign Execution Broker: certificate-bound authority in agentic control planes](https://arxiv.org/pdf/2606.20520)
- [Type-checked compliance: deterministic guardrails using Lean 4](https://arxiv.org/html/2604.01483v1)

## Maintenance

This page is a snapshot dated **July 2026**. It makes dated competitive claims
that will rot. Revisit it when a release goes out, and treat any claim of the
form "nobody else does X" as expiring unless re-checked.
