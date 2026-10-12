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
use nucleus_sdk::{Nucleus, Intent};

# async fn example() -> nucleus_sdk::Result<()> {
// Inside a pod, the runtime names the workload's own door, a Unix socket
// the tool-proxy admits by the caller's uid: no secret to hold or pass.
let door = std::env::var("NUCLEUS_TOOL_PROXY_URL")
    .unwrap_or_else(|_| "unix:///run/nucleus-door/workload.sock".into());
let nucleus = Nucleus::builder().proxy_url(door).build()?;

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

### Transport security

Use HTTPS for remote TCP endpoints and whenever configuring mTLS. Plain HTTP is
accepted only for literal loopback addresses (`127.0.0.1` or `::1`) without mTLS;
use a Unix socket for the workload door. Redirects are disabled so signed requests
cannot be forwarded to a different endpoint. Local HTTP bypasses environment proxies.

For custom connection settings, use `ProxyClient::with_client_builder`, which
requires HTTPS and applies the redirect policy before building. It replaces
`with_client`: an already-built client's redirect policy cannot be verified.
