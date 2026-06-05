# portcullis-effects

Sealed effect traits — the primary surface for all I/O in nucleus, where every
operation goes through a policy-enforced channel.

[![docs.rs](https://img.shields.io/docsrs/portcullis-effects)](https://docs.rs/portcullis-effects)

Effect types replace the raw capability lattice as the *primary* public surface.
Instead of building a `CapabilityLattice` and remembering to call preflight,
callers receive a concrete effect handler whose only public constructor,
`production_effects`, **requires a policy**. Bypassing policy is structurally
impossible: the real handler is unconstructible outside this crate, so policy is
checked at every method call before any I/O occurs.

```text
Old surface:  caller builds CapabilityLattice, calls preflight, manually enforces
New surface:  caller receives impl FileEffect + WebEffect + …,
              policy is checked at every method call before I/O occurs
```

## Effect traits

| Trait | I/O |
|---|---|
| `FileEffect` | read / write / search the filesystem |
| `WebEffect` | outbound fetch / search |
| `ShellEffect` | command execution (`ShellOutput`) |
| `GitEffect` | git operations |
| `AgentSpawnEffect` | spawn sub-agents |

## Usage

```rust,ignore
use portcullis_effects::{production_effects, FileEffect, WebEffect};
use portcullis_core::{CapabilityLattice, CapabilityLevel};

let policy = CapabilityLattice {
    read_files: CapabilityLevel::Always,
    web_fetch: CapabilityLevel::LowRisk,
    ..CapabilityLattice::bottom()
};
let fx = production_effects(policy);

// Policy is checked here — no separate preflight call.
let contents = fx.read(std::path::Path::new("src/main.rs"))?;
fx.fetch("https://example.com")?;
```

## Test doubles

| Handler | Use |
|---|---|
| `DenyAllEffects` | rejects everything — exercise deny paths |
| `RecordingEffects` | records every call (`calls()`) — assert what was invoked |
| `AllowListEffects` | allow a fixed set — targeted positive tests |

Async variants live in the `async_traits` module.

## License

MIT
