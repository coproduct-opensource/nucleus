# Nucleus Python SDK (Draft)

Intent-first SDK for Nucleus. This package wraps the node and tool-proxy APIs and exposes user-facing intents.

## Status

Draft. API will change.

## Quick Start

```python
from nucleus_sdk import Nucleus, Intent
from nucleus_sdk.auth import MtlsConfig

mtls = MtlsConfig(
    cert_path="/var/run/nucleus/svid.pem",
    key_path="/var/run/nucleus/key.pem",
    ca_bundle="/var/run/nucleus/bundle.pem",
)

client = Nucleus(proxy_url="https://tool-proxy.local:8443", mtls=mtls)

with client.intent(Intent.FIX_ISSUE, work_dir=".") as sess:
    sess.read("README.md")
    sess.run(["rg", "TODO", "-n"])
    sess.write("notes.md", "todo list")
```

## Intents

Each intent maps to a built-in Nucleus profile. The SDK exposes intent metadata so users can see what is allowed vs gated.

- `research_web` -> `web_research`
- `code_review` -> `code_review`
- `fix_issue` -> `fix_issue`
- `generate_code` -> `codegen`
- `release` -> `release`
- `database_client` -> `database_client`
- `read_only` -> `read_only`
- `edit_only` -> `edit_only`
- `local_dev` -> `local_dev`
- `network_only` -> `network_only`

## Pod Lifecycle

Staticless path: connect directly to `nucleus-tool-proxy` with mTLS and skip node orchestration. If you need pod creation, you will currently need a node client with legacy HMAC or a gRPC client (not included yet).

## Authentication

Preferred: SPIFFE mTLS (staticless). The proxy accepts mTLS first and skips HMAC when a valid SPIFFE ID is present.

Legacy fallback: HMAC signing using the same header format as the CLI examples. This is deprecated on the node side and should be avoided where possible.

## Error Model

`NucleusError` wraps proxy errors with `kind` and optional `operation` fields, including:

- `approval_required`
- `path_denied`
- `command_denied`
- `budget_exhausted`
- `time_violation`
- `trifecta_blocked`
- `insufficient_capability`
