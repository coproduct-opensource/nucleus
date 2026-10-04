# Enterprise Buyer Adversarial North Star

Nucleus is $99/repo/month for the complete AI agent governance lifecycle: Constitutional Gate (before), Permission Telemetry (during), Fleet Lockdown (emergency), and Compliance Export (after).

Before any agent runs, the Constitutional Gate PR check blocks capability escalation -- if an agent's manifest requests more permissions than its profile allows, the PR fails. The gate produces a signed receipt with content-hash binding, so you can prove what was approved.

During execution, every tool call verdict is emitted as an OTLP span with the agent's SPIFFE identity, all 7 capability dimensions, exposure state (private data, untrusted content, exfiltration vector), and lattice checksum. Your existing observability stack (Grafana, Datadog, Splunk) shows real-time permission state across your entire agent fleet. No other product monitors what agents are ALLOWED to do.

In an emergency, `nucleus lockdown` drops all agents to read-only in under one second via gRPC streaming. The witness chain records exactly what each agent touched before, during, and after the incident. You get a full incident timeline without manual forensics.

After the incident, `nucleus audit export --format soc2` generates the SOC 2 Type II evidence package from the witness chain. The same data feeds EU AI Act Article 14 transparency reports. One data source, two compliance frameworks.

The competitive moat: 62 Kani bounded model checking proofs and a Lean 4 HeytingAlgebra instance on the production permission type, kernel-checked by Mathlib. No competitor has formal verification on agent permissions. The proofs are open source -- you can audit them yourself.
