# nucleus-sdk

Rust SDK for building sandboxed AI agents with
[nucleus](https://github.com/coproduct-opensource/nucleus).

[![docs.rs](https://img.shields.io/docsrs/nucleus-sdk)](https://docs.rs/nucleus-sdk)

A unified client for nucleus services, where every tool call an agent makes is
enforced by the [portcullis](../portcullis) permission lattice inside the pod.

- **`ProxyClient`** — HTTP client for the tool-proxy (file I/O, execution, web access)
- **`NodeClient`** — gRPC client for nucleus-node (pod lifecycle, streaming logs)
- **`Nucleus`** — unified facade combining both clients
- **`Intent`** — high-level permission profiles mapped to portcullis policies

## Quick start

```rust,no_run
use nucleus_sdk::{Nucleus, Intent, HmacAuth};

# async fn example() -> nucleus_sdk::Result<()> {
// Connect to a running tool-proxy
let nucleus = Nucleus::builder()
    .proxy_url("http://127.0.0.1:8080")
    .auth(HmacAuth::new(b"my-secret", Some("agent")))
    .build()?;

// Open a scoped session with uninhabitable-state-safe permissions
let session = nucleus.intent(Intent::FixIssue).await?;

// All operations enforced by portcullis inside the pod
let source = session.read("src/main.rs").await?;
session.write("src/main.rs", &source.replace("bug", "fix")).await?;
# Ok(())
# }
```

## Intent profiles

An `Intent` is a named permission profile compiled to a portcullis policy, so an
agent gets exactly the capabilities its task needs and no more:

| Intent | Capabilities |
|---|---|
| `ResearchWeb` | read + web_fetch + web_search; no write/exec |
| `CodeReview` | read + glob + grep; no write, no network |
| `FixIssue` | full code editing with uninhabitable-state obligations |
| `GenerateCode` | write files in workspace; network-isolated |
| `Release` | git push + PR operations; CI-gated |
| `DatabaseClient` | network to allowed hosts; no file write |
| `ReadOnly` | observe files; no mutations |
| `EditOnly` | write files; no execution or network |
| `LocalDev` | permissive local environment |
| `NetworkOnly` | web operations; no filesystem access |
| `Orchestrate` | manage sub-pods; no direct file/network access |

## Architecture

```text
┌─────────────────────────────────────────┐
│  nucleus-sdk (this crate)               │
│  ┌─────────┐  ┌──────────┐  ┌────────┐ │
│  │ Nucleus  │──│  Intent  │──│ Auth   │ │
│  │ (facade) │  │ (profile)│  │ (HMAC) │ │
│  └────┬─────┘  └──────────┘  └────────┘ │
│       │                                  │
│  ┌────┴────────┐  ┌────────────────┐    │
│  │ ProxyClient │  │  NodeClient    │    │
│  │ (HTTP)      │  │  (gRPC/tonic)  │    │
│  └─────────────┘  └────────────────┘    │
└──────────────────────────────────────────┘
       │                    │
       ▼                    ▼
  tool-proxy            nucleus-node
  (in-pod HTTP)         (gRPC service)
```

## Feature flags

- **`identity`** — SPIFFE identity support via [`nucleus-identity`](../nucleus-identity):
  mTLS client configuration and workload certificate management.

## License

MIT
