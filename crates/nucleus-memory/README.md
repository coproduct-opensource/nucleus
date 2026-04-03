# nucleus-memory

**Governed memory for AI agents — IFC labels, integrity tracking, poisoning detection.**

The only memory library with per-entry security labels. Detect MINJA-style memory poisoning attacks at the data level, not with heuristics.

## Why?

MINJA (NeurIPS 2025) achieved **95% injection success** against agent memory. MemoryGraft implants fake experiences. OWASP ASI06 (2026) added Memory Poisoning to the Agentic Top 10.

Every competitor offers pattern-matching filters. Nucleus tracks **per-entry IFC labels** — confidentiality, integrity, authority class, and provenance bitflags.

## Quick Start

```rust,ignore
use nucleus_memory::{GovernedMemory, MemoryLabel, MemoryAuthority};

let mut mem = GovernedMemory::new();
let now = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_secs();

// Store with default labels (Internal confidentiality, Trusted integrity)
mem.write("user_preference", "dark mode".to_string(), now, None);

// Store web-derived data with adversarial labels
mem.write_governed(
    "search_result",
    "data from web".to_string(),
    MemoryLabel::from_integrity(portcullis_core::IntegLevel::Adversarial),
    MemoryAuthority::MayInform,  // can inform, cannot authorize actions
    now,
    None,
);

// Detect poisoned entries
let poisoned = mem.poisoned_entries(now);
for (key, entry) in &poisoned {
    eprintln!("WARNING: poisoned memory entry: {key}");
}
```

## Memory Labels

| Label | Confidentiality | Integrity | Use for |
|-------|----------------|-----------|---------|
| Default | Internal | Trusted | User preferences, local data |
| Adversarial | Public | Adversarial | Web content, untrusted APIs |
| Secret | Secret | Trusted | API keys, credentials |

## Authority Classes

| Authority | Can inform model? | Can authorize actions? |
|-----------|------------------|----------------------|
| `MayAuthorize` | Yes | Yes |
| `MayInform` | Yes | No — model sees it but can't act on it |
| `MayNotAuthorize` | Read-only | No |

## Provenance Tracking

Each entry carries provenance bitflags:
- `USER` — directly from user input
- `WEB` — from web search/fetch
- `TOOL` — from a tool invocation
- `MODEL` — AI-generated
- `SYSTEM` — from system/env
- `MEMORY` — from another memory entry

## Poisoning Detection

`poisoned_entries()` returns entries where:
- Integrity was downgraded (e.g., Trusted → Adversarial)
- Provenance includes `WEB` but authority is `MayAuthorize`
- Entry was overwritten with a different provenance source

## License

MIT
