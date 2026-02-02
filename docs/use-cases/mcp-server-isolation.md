# MCP Server Isolation

> Run Model Context Protocol servers in isolated Firecracker VMs.

## The Challenge

MCP (Model Context Protocol) servers provide tools to AI assistants. Each server runs with the privileges of the host process, meaning:

- A compromised MCP server can access all host resources
- Multiple MCP servers share the same security boundary
- No isolation between different tool providers

## Solution: Per-Server Firecracker VMs

Nucleus can run each MCP server in its own microVM:

```
┌─────────────────────────────────────────────────────────┐
│  Claude Desktop / MCP Client                            │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │ filesystem  │  │   github    │  │  database   │     │
│  │   server    │  │   server    │  │   server    │     │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘     │
│         │                │                │             │
│         ▼                ▼                ▼             │
│  ┌─────────────────────────────────────────────────────┐│
│  │              nucleus-node                           ││
│  └─────────────────────────────────────────────────────┘│
│         │                │                │             │
│         ▼                ▼                ▼             │
│  ┌───────────┐    ┌───────────┐    ┌───────────┐       │
│  │ Firecracker│    │ Firecracker│    │ Firecracker│       │
│  │   VM #1   │    │   VM #2   │    │   VM #3   │       │
│  │ /home only│    │ github.com│    │ postgres  │       │
│  └───────────┘    └───────────┘    └───────────┘       │
└─────────────────────────────────────────────────────────┘
```

## Benefits

| Isolation Property | Guarantee |
|-------------------|-----------|
| **Filesystem** | Each server sees only its allowed paths |
| **Network** | Per-server egress allowlists |
| **Memory** | Separate address spaces |
| **Secrets** | Server A can't access Server B's credentials |

## Configuration

```toml
# MCP server: filesystem
[servers.filesystem]
vm_profile = "filesystem-readonly"
allowed_paths = ["/home/user/documents"]
network = "none"

# MCP server: github
[servers.github]
vm_profile = "network-only"
allowed_hosts = ["api.github.com"]
secrets = ["GITHUB_TOKEN"]

# MCP server: database
[servers.database]
vm_profile = "database-client"
allowed_hosts = ["db.internal:5432"]
secrets = ["DATABASE_URL"]
```

## Status

MCP integration in development. See [architecture docs](../architecture/mcp.md) for design.
