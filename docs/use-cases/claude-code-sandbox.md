# Claude Code Sandbox

> Isolate Claude Code's tool execution without sacrificing developer productivity.

## The Challenge

Claude Code executes shell commands, reads/writes files, and makes network requests on behalf of developers. While powerful, this means a prompt injection or confused deputy attack could:

- Modify source code maliciously
- Exfiltrate API keys from `.env` files
- Install compromised dependencies
- Push unauthorized commits

## Solution: Nucleus as Execution Backend

```
┌────────────────────────────────────────────────────────┐
│  Claude Code (Host)                                    │
│  ├── Anthropic API key          ← Stays on host       │
│  ├── Git credentials            ← Stays on host       │
│  └── SSH keys                   ← Stays on host       │
│                                                        │
│  Tool Request: "npm install && npm run build"          │
│         │                                              │
│         ▼                                              │
│  ┌────────────────────────────────────────────────────┐│
│  │  Firecracker microVM                               ││
│  │  ├── Project directory mounted at /workspace       ││
│  │  ├── npm registry access allowed                   ││
│  │  ├── No access to ~/.ssh, ~/.gitconfig            ││
│  │  └── Build artifacts returned to host             ││
│  └────────────────────────────────────────────────────┘│
└────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install nucleus
nucleus setup

# Configure Claude Code to use nucleus backend
# (Integration instructions pending Claude Code plugin system)
```

## Permission Profile: Developer Workflow

```toml
[filesystem]
allowed_paths = ["/workspace"]
denied_paths = ["**/.env", "**/.env.*", "**/secrets.*"]

[network]
allowed_hosts = [
  "registry.npmjs.org",
  "pypi.org",
  "crates.io",
  "api.github.com",
]

[capabilities]
allow_shell = true    # Needed for builds
allow_sudo = false
max_memory_mb = 4096
max_cpu_seconds = 300
```

## Benefits

| Risk | Mitigation |
|------|------------|
| Malicious dependency | Runs in isolated VM, can't access host |
| .env exfiltration | .env files denied by default |
| Git credential theft | Credentials stay on host |
| Supply chain attack | Network limited to package registries |

## Status

Integration with Claude Code pending. See [GitHub issue](#) for progress.
