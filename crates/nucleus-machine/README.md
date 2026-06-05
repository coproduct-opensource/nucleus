# nucleus-machine

An execution-substrate abstraction for agent runtimes.

A `MachineDriver` is a microVM lifecycle backend. The agent control plane's
reconciler depends only on this trait, so the substrate is swappable and never
load-bearing lock-in (see
[`docs/rfcs/agent-control-plane-on-fly.md`](../../docs/rfcs/agent-control-plane-on-fly.md)).

## Lifecycle

```text
create ──► Created ──start──► Active ──suspend──► Frozen
                               │  ▲                 │
                            stop│  └──────start─────┘
                               ▼
                            Stopped ──start──► Active
                               │
   (any non-terminal) ──destroy──► Destroyed
```

The key primitive is `suspend`: on Fly this snapshots VM memory to disk so an
idle agent costs ~nothing and resumes in ~ms on the next message — the
efficiency win that is structurally impossible on Kubernetes. `Frozen` keeps a
memory snapshot (warm resume); `Stopped` does not (cold start required).

## Backends

| Driver | Status | Notes |
|---|---|---|
| `MockMachineDriver` | **Fully implemented** | In-memory state machine that enforces the same lifecycle transitions a real backend would. Lets reconciler logic be exercised with zero infrastructure. |
| `FlyMachineDriver` | **Skeleton** | Backend for [Fly.io Machines](https://fly.io/docs/machines/) (Firecracker microVMs with native `suspend`/`start`). The Machines-API *endpoint mapping* (`endpoint()`) is implemented and tested. The HTTP transport is a documented P0 TODO: the trait methods return `MachineError::NotWired` rather than faking calls. |

> The Fly transport is intentionally kept out of this crate so the dependency
> stays transport-free until the control plane needs it. `FlyMachineDriver` does
> **not** pretend to perform real calls — it fails honestly with `NotWired`.

## Example

```rust
use nucleus_machine::{MachineDriver, MockMachineDriver, MachineSpec, MachineState};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let driver = MockMachineDriver::new();
let id = driver.create(&MachineSpec {
    image: "registry.fly.io/agent:latest".into(),
    region: Some("sjc".into()),
    cpus: 1,
    memory_mb: 512,
    env: Default::default(),
}).await?;

driver.start(&id).await?;                          // Active
driver.suspend(&id).await?;                         // Frozen (memory snapshot)
assert_eq!(driver.status(&id).await?, MachineState::Frozen);
driver.start(&id).await?;                           // warm resume → Active
driver.destroy(&id).await?;                         // terminal
# Ok(())
# }
```

## Tests

```bash
cargo test -p nucleus-machine
```

Covers the full mock lifecycle, invalid-transition rejection, unknown-id
handling, the Fly endpoint mapping, and the honestly-unwired Fly transport.

## License

MIT
