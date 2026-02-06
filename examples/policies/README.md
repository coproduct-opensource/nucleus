# Example Policies

This directory contains example CEL-based constraint policies for nucleus.

## Policy Structure

Each policy is a YAML file with:

```yaml
name: policy-name
description: Human-readable description
enforce_trifecta: true  # Enable lethal trifecta protection

constraints:
  - name: constraint-name
    description: What this constraint does
    condition: |
      CEL expression that returns true when obligations apply
    obligations:
      - operation_name  # Operations requiring approval
```

## Available Variables in CEL

| Variable | Type | Description |
|----------|------|-------------|
| `operation` | string | Current operation (`read_files`, `write_files`, etc.) |
| `path` | string | File path being accessed |
| `url` | string | URL being fetched |
| `trifecta_risk` | string | `none`, `low`, `medium`, `complete` |
| `budget_remaining` | float | Remaining budget fraction (0.0-1.0) |
| `has_approval` | bool | Whether human approval was granted |
| `request_rate` | int | Requests per minute |
| `isolation.process` | string | `shared`, `namespaced`, `microvm` |
| `isolation.file` | string | `unrestricted`, `sandboxed`, `readonly`, `ephemeral` |
| `isolation.network` | string | `host`, `namespaced`, `filtered`, `airgapped` |

## Available Operations

| Operation | Description |
|-----------|-------------|
| `read_files` | Reading files |
| `write_files` | Writing new files |
| `edit_files` | Editing existing files |
| `run_bash` | Running shell commands |
| `glob_search` | Searching by file pattern |
| `grep_search` | Searching file contents |
| `web_search` | Searching the web |
| `web_fetch` | Fetching web content |
| `git_commit` | Creating git commits |
| `git_push` | Pushing to remote |
| `create_pr` | Creating pull requests |

## Example Policies

### `basic-codegen.yaml`
Permissive policy for code generation. Restricts operations outside the workspace directory.

### `secure-review.yaml`
Read-heavy policy for code review. All writes, edits, and git operations require approval.

### `rate-limited.yaml`
Demonstrates rate limiting. Operations require approval when request rates exceed thresholds.

### `research-mode.yaml`
Read-only research policy. No file modifications, git, or bash without approval.

### `trifecta-demo.yaml`
Demonstrates the lethal trifecta protection (private data + untrusted content + exfiltration).

### `isolation-aware.yaml`
Demonstrates isolation-based constraints. Different operations require different levels of process, file, and network isolation.

## Isolation Levels

The isolation lattice has three dimensions:

### Process Isolation
| Level | Description |
|-------|-------------|
| `shared` | Same process space (localhost) |
| `namespaced` | Linux namespaces (pid, ipc, mount) |
| `microvm` | Firecracker microVM with separate kernel |

### File Isolation
| Level | Description |
|-------|-------------|
| `unrestricted` | Full filesystem access |
| `sandboxed` | cap-std directory capabilities |
| `readonly` | Immutable root filesystem |
| `ephemeral` | Scratch-only, no persistence |

### Network Isolation
| Level | Description |
|-------|-------------|
| `host` | Host network stack |
| `namespaced` | Network namespace with veth bridge |
| `filtered` | Allowlist-only firewall |
| `airgapped` | No network (vsock only) |

## The Lethal Trifecta

The `enforce_trifecta: true` setting (default) protects against the combination of:

1. **Private data access** - Reading files (potential secrets)
2. **Untrusted content** - Fetching from the web (potential prompt injection)
3. **Exfiltration capability** - Git push, PR creation, web requests

When all three are present, exfiltration operations automatically require approval.

## Loading Policies

```rust
use lattice_guard::constraint::spec::PolicySpec;
use std::fs;

let yaml = fs::read_to_string("policies/basic-codegen.yaml")?;
let spec = PolicySpec::from_yaml(&yaml)?;
let policy = spec.build()?;

// Use as a nucleus
use lattice_guard::frame::Nucleus;
let perms = PermissionLattice::permissive();
let safe = policy.apply(&perms);
```
