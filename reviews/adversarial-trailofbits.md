# Trail of Bits Adversarial North Star — PajaMAS Attack Surface

Trail of Bits demonstrated in pajaMAS (July 2025) that multi-agent system hijacking manipulates control flow by exploiting inter-agent communication. Their conclusion: "runtime controls based on capability models are the most promising defense." Nucleus claims to be that defense. A Trail of Bits researcher would test whether our capability model actually prevents the attacks they documented.

## Claim 1: The permission lattice prevents confused deputy attacks

In pajaMAS, Agent A tricks Agent B into performing actions that B is authorized for but A is not. Nucleus prevents this because each agent has its own PermissionLattice, and delegation uses meet() — the delegated agent can never have MORE permissions than the delegator. The meet operation is proven monotonically decreasing by the Lean 4 HeytingAlgebra proof. An agent cannot delegate permissions it doesn't have.

## Claim 2: The tool-proxy intercept prevents tool misuse (OWASP ASI02)

Every tool call passes through the nucleus-tool-proxy, which checks the permission lattice before execution. An agent cannot directly access the filesystem, network, or git — it must go through the proxy. The proxy is the TCB (Trusted Computing Base), and the lattice operations within it are formally verified.

## Claim 3: The uninhabitable state detection prevents exfiltration chains

The IncompatibilityConstraint detects when an agent has simultaneous access to private data (read), untrusted content (web), and an exfiltration vector (push/PR). When all three are present, the constraint adds approval obligations. This prevents the classic prompt injection → data access → exfiltration chain.

## Claim 4: The lockdown mechanism provides "targeted intervention" (Bessemer gap)

Bessemer identifies "targeted intervention — in-flight action-level halting without workflow disruption" as "the most underdeveloped" capability in agent security. Nucleus's fleet lockdown via gRPC streaming provides sub-second targeted intervention: drop specific agents (by pod ID or label selector) to read-only while others continue operating.

## Claim 5: The witness chain provides non-repudiable forensics

Every tool call verdict is recorded in an HMAC-signed, hash-chained audit log with drand-anchored timestamps. After an incident, the witness chain reconstructs exactly what each agent did, when, and under what permissions. The chain is tamper-evident — modifying an entry breaks the hash chain.

## What a Trail of Bits researcher would test

- "Can I perform a pajaMAS-style confused deputy attack through the MCP path? Does the MCP path check the permission lattice?"
- "If I have web_fetch: Always and read_files: Always, can I exfiltrate private data via a URL parameter in a web_fetch call? Does the uninhabitable constraint actually trigger?"
- "Can I escalate my CapabilityLevel from LowRisk to Always by exploiting the approval flow? What if I forge an approval token?"
- "The lockdown uses an AtomicBool. Can I race the lockdown by sending a tool call that's already past the check when the bool flips?"
- "The audit chain uses HMAC with a shared secret. If I compromise the secret, I can forge the entire chain. Where is the secret stored?"
- "The SPIFFE identity system checks for attestation presence but does it verify cryptographic signatures? Can I attach fake attestation bytes?"
- "The FunsExternal.lean defines PartialOrd::le using toNat. The Rust PartialOrd is derived (compiler-generated). How do I know the derived impl matches toNat ordering? What if the Rust compiler reorders discriminants?"
- "Can I trigger a denial of service by flooding the lockdown gRPC stream with LockdownCommand messages?"
- "The VerdictSink records verdicts but what prevents an agent from making 10,000 rapid tool calls before the first verdict is even logged?"
