# nucleus-ifc

**Information Flow Control for AI agents — the only IFC library shipping in production.**

Track how data flows through your agent session. Detect taint from untrusted sources. Block unsafe actions at the data level — not just the capability level.

## Why IFC?

The EchoLeak attack (CVE-2025-32711) worked because Copilot treated PowerPoint speaker notes as trusted input. A hidden prompt injection in the notes exfiltrated the user's emails. Every defense on the market uses pattern matching to detect injections. Nucleus uses **information flow control** — the flow graph tracks WHERE data came from, and the math proves tainted data can't reach privileged sinks.

**Zero pattern matching. Zero false positives on clean workflows. Formally verified (62 Kani proofs, 165 Lean 4 theorems).**

## Quick Start

```rust
use nucleus_ifc::{FlowTracker, NodeKind};

let mut tracker = FlowTracker::new();

// Web content enters with Adversarial integrity
let web = tracker.observe(NodeKind::WebContent)?;

// Model reads it — taint propagates through the causal DAG
let plan = tracker.observe_with_parents(NodeKind::ModelPlan, &[web])?;

// Is it safe to write based on this data?
let check = tracker.check_safety(&[plan], true);
assert!(check.is_denied()); // Adversarial ancestry → blocked
```

## How It Works

```
UserPrompt ──────────────── Trusted, Directive
      │
FileRead ────────────────── Trusted, Deterministic
      │
WebContent ──────────────── Adversarial, NoAuthority
      │
ModelPlan(web + file) ───── Adversarial (taint joins)
      │
WriteFiles ──────────────── DENIED (adversarial ancestry)
```

Data enters the flow graph as **observations** with intrinsic labels:
- `UserPrompt`: Trusted integrity, Directive authority
- `WebContent`: Adversarial integrity, NoAuthority
- `FileRead`: Trusted integrity, Deterministic derivation
- `DeterministicBind`: Trusted, Deterministic (model excluded)

When you observe a node with parents, labels **join** (Denning's lattice):
- `Trusted.join(Adversarial) = Adversarial` — taint propagates
- `Directive.join(NoAuthority) = NoAuthority` — authority can't escalate

`check_safety()` inspects the resulting label and blocks if unsafe.

## API

```rust
// Create a tracker
let mut t = FlowTracker::new();

// Observe data entering the session
let id = t.observe(NodeKind::WebContent)?;
let id = t.observe_with_parents(NodeKind::ModelPlan, &[parent1, parent2])?;

// Inspect labels
let label = t.label(id);  // IFCLabel { integrity, authority, derivation, ... }

// Safety checks
let check = t.check_safety(&[id], requires_authority);
check.is_safe()    // true if clean
check.is_denied()  // true if tainted

// Session-level queries
t.is_tainted()      // any adversarial node?
t.has_ai_derived()  // any AI-derived node?
t.node_count()      // total observations
```

## Node Kinds

| Kind | Integrity | Authority | Use for |
|------|-----------|-----------|---------|
| `UserPrompt` | Trusted | Directive | User messages |
| `FileRead` | Trusted | Directive | Local file reads |
| `WebContent` | Adversarial | NoAuthority | Web search, fetch |
| `ModelPlan` | *inherited* | *inherited* | Model reasoning |
| `DeterministicBind` | Trusted | NoAuthority | Parser output (model excluded) |
| `ToolResponse` | *inherited* | *inherited* | Tool outputs |
| `Secret` | Trusted | NoAuthority | API keys, credentials |

## FAQ

**Q: Doesn't this block legitimate AI workflows?**
A: No. Clean workflows (user prompt → file read → model → write) pass with zero false positives. The IFC system only fires when actual security boundaries are crossed. See `cargo run -p nucleus-ifc --example ifc_demo`.

**Q: What about the Adversarial → Trusted transition?**
A: Controlled declassification. Explicit, auditable, rate-limited. An attacker can't silently upgrade taint.

**Q: How is this different from FIDES (Microsoft Research)?**
A: FIDES operates at the planner level (Python, AgentDojo). Nucleus operates at the kernel level (Rust, formally verified). FIDES tracks message-level labels. Nucleus tracks per-node in a causal DAG with derivation classes.

## License

MIT
