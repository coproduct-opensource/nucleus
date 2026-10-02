# CISO Buyer Adversarial North Star — Why Nucleus Over Alternatives?

A CISO evaluating AI agent security tools in 2026 has real alternatives. Nucleus must win on features, not vibes. Here are the claims a buyer would challenge:

## Claim 1: No existing product monitors agent permissions in real-time

Competitors monitor prompts, tokens, and latency (Langfuse, Braintrust, Helicone, LangSmith). Some monitor tool calls (Galileo, Arthur AI). But none monitor the PERMISSION LATTICE — what agents are ALLOWED to do, not what they DID. Nucleus is the only product where a CISO can see "Agent X has write_files: Always, git_push: LowRisk" in their existing Grafana dashboard via OTLP. This is a new observability category.

## Claim 2: Kill switches don't work if the agent writes the policy

Stanford Law Review (2026) identified the fundamental problem: most AI governance tools let the agent modify its own policy files. Nucleus solves this with a formally verified Heyting algebra — the permission lattice is a mathematical structure proven by the Lean kernel to be non-escalatable. An agent cannot `meet` its way to higher permissions because meet is monotonically decreasing. No competitor has formal verification on their permission model. AWS Cedar uses Lean 4 but for authorization policy evaluation, not algebraic structure proofs on the permission type itself.

## Claim 3: $99/repo/month beats the alternative of building in-house

The alternative to Nucleus is: (a) build your own agent sandbox with bubblewrap/Firecracker, (b) write your own permission system, (c) build your own audit pipeline, (d) hope you get the math right. Companies like Anthropic, OpenAI, and Google have internal versions but don't sell them. The build-vs-buy math: a senior security engineer costs $250K+/year. Nucleus at $99/repo for 50 repos is $60K/year — less than one headcount, with formal proofs no single engineer would produce.

## Claim 4: Nucleus is the only open-core agent security product with formal proofs

Open-source competitors (gVisor, Firecracker, bubblewrap) provide container/VM isolation but no permission semantics, no lattice, no telemetry, no fleet lockdown. Commercial competitors (Robust Intelligence, Lakera, Prompt Security, CalypsoAI) focus on prompt injection and content filtering — they protect the MODEL, not the AGENT'S ACTIONS. Nucleus protects what the agent can DO (file writes, command execution, network access, git push) with per-dimension capability levels and formal proofs that the permission model is sound.

## Claim 5: The compliance export is a real SOC 2 artifact, not a checkbox

`nucleus audit export --format soc2` generates evidence from the same witness chain used for runtime enforcement. The audit trail has HMAC-signed entries with content-hash binding, drand-anchored timestamps, and per-executor signatures. This is not a separate compliance tool bolted on after the fact — the same data that enforces permissions generates the compliance report. An auditor can trace from the SOC 2 evidence package back to the exact permission verdict that produced it.

## What a skeptical CISO buyer would challenge

- "Show me Langfuse/Braintrust/LangSmith side by side — what exactly can't they do?"
- "AWS Cedar already uses Lean 4 — how is your formal verification different?"
- "Why wouldn't I just use gVisor + OPA + custom OTLP and save the $99/repo?"
- "Your lockdown takes 'under one second' — prove it. Show me the latency numbers."
- "What happens when my agent uses MCP instead of your HTTP proxy? Does your telemetry still work?"
- "How many production deployments do you have? Who else is using this?"
- "Formal proofs sound nice but my team can't read Lean 4 — how do I audit this?"
