# Nucleus Use Cases

Nucleus provides hardware-isolated sandboxing for AI agents. While the architecture is general-purpose, certain use cases benefit most from defense-in-depth isolation.

## Why Now

January 2026 brought AI agent security into sharp focus:

- **Moltbook breach** (Jan 31): Unsecured database allowed hijacking of 770K+ AI agents
- **Palo Alto "Lethal Trifecta" research**: Identified the dangerous combination of private data access + untrusted content + external communication
- **OpenClaw adoption**: 100K+ GitHub stars, running in enterprise environments with root filesystem access

The industry is deploying agents faster than security practices can evolve. Nucleus provides a hardened execution layer that doesn't require perfect configuration—isolation is architectural, not optional.

## Use Cases

| Use Case | Risk Profile | Nucleus Benefit |
|----------|--------------|-----------------|
| [OpenClaw Hardening](./openclaw-hardening.md) | Critical - full system access | Break the lethal trifecta |
| [Claude Code Sandbox](./claude-code-sandbox.md) | High - code execution | Isolated tool execution |
| [MCP Server Isolation](./mcp-server-isolation.md) | Medium - tool calls | Per-tool sandboxing |
| [Enterprise AI Agents](./enterprise-ai-agents.md) | Variable - compliance | Audit trails, NIST compliance |

## Quick Comparison

```
┌─────────────────────────────────────────────────────────────────┐
│                     Without Nucleus                              │
├─────────────────────────────────────────────────────────────────┤
│  AI Agent ──► Tools ──► Host Filesystem ──► Network ──► World   │
│     │                        │                                   │
│     └── Credentials, API keys, browser sessions all accessible  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      With Nucleus                                │
├─────────────────────────────────────────────────────────────────┤
│  AI Agent (host) ──► nucleus-node ──► Firecracker VM            │
│       │                                    │                     │
│       │  API keys stay here          Only /workspace visible     │
│       │                              Network egress filtered     │
│       │                              No shell escape possible    │
│       │                                    │                     │
│       └────────── Signed results ◄─────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

## Getting Started

```bash
# Install
cargo install nucleus-node
cargo install nucleus-cli

# Setup (macOS with Lima VM, or native Linux)
nucleus setup

# Verify
nucleus doctor
```

See individual use case docs for integration guides.
