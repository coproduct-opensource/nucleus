# Pitch draft — the lockdown framing

*A point-in-time marketing draft, not a statement of the objective.* It lived at the
repository root as `north-star.md`, a fourth positioning referenced by nothing, and
was moved here by [ADR 0005](../docs/adr/0005-delegatable-agency.md). The canonical
objective is [`NORTH_STAR.md`](../NORTH_STAR.md); the long form and the CI-parsed
claim ledgers are [`docs/north-star.md`](../docs/north-star.md).

---

When an AI agent escapes its sandbox — and at a 93% jailbreak success rate, it will — `nucleus lockdown` drops every agent in your fleet to read-only in under one second, with a signed witness chain proving exactly what each agent touched before, during, and after the incident. The lockdown is enforced by a permission lattice that is a formally verified Heyting algebra — not a policy file an agent can edit, but a mathematical structure the Lean kernel has proven cannot be escalated. Every tool call is intercepted by a kernel-level proxy, exposure-classified by sandbox observation, and attested with per-executor cryptographic signatures. The incident replay reconstructs a visual timeline from the witness chain, and the compliance export generates the SOC 2 / EU AI Act evidence package from the same data. The formal proofs are open source. The kill switch is the product.
