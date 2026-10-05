# Naming the agent `nucleus run` and `nucleus shell` launch

Nucleus has no default agent. `run` and `shell` launch the agent CLI you name,
and refuse to start until you name one:

```bash
nucleus run   --agent <PROGRAM> [OPTIONS] "task" [-- AGENT_ARGS...]
nucleus shell --agent <PROGRAM> [OPTIONS]        [-- AGENT_ARGS...]
```

or, equivalently,

```bash
export NUCLEUS_AGENT=<PROGRAM>
```

or, once, in `~/.config/nucleus/config.toml`:

```toml
[agent]
command = ["<PROGRAM>", "<LEADING-ARG>"]
```

`--agent` (or `NUCLEUS_AGENT`) wins over the config file. Arguments after `--`
follow the config's own arguments.

## Where the agent runs

**In the pod, by default.** `nucleus run` against a node (Firecracker, or the
Apple microVM host) makes the agent the pod's workload: the guest's tool-proxy
starts it inside the microVM, as an unprivileged uid, and it reaches its tools
through the guest's MCP bridge (`/usr/local/bin/nucleus-mcp`). Nothing from
this host's environment is passed in, and `--env` is refused for a pod run.

So the agent must be **in the guest image**: name it by its absolute path in the
rootfs the pod boots (`--rootfs-path`), or by a name on the guest's `PATH`.
Nucleus does not copy a host binary into the guest; a host-relative path
(`./agent`, `~/bin/agent`) is refused, and a missing program is reported by the
node as "the agent program was not found in the guest image".

**On this host, only when you say so.** `run --local`, `run --hook` and `shell`
launch the agent on this machine, as you, outside any microVM. They refuse to
unless you pass `--unsandboxed`; with it they print a banner and append a record
to `~/.config/nucleus/audit/host-agent-launches.jsonl`.

## The launch protocol

Nucleus builds the agent's command line as:

```
<PROGRAM> <AGENT_ARGS...>
  --setting-sources '' --strict-mcp-config      # confinement (always)
  --settings <file>                             # registers the nucleus PreToolUse mediation hook
  --mcp-config <file>                           # the nucleus MCP server (tool-proxy modes)
  --allowedTools <nucleus tools> --disallowedTools <built-ins>
  ... <prompt>
```

In a pod the same command line is the workload's argv, with two differences:
`--mcp-config` carries the configuration document itself (no host file is
visible in the guest; it names only the guest's bridge), and there is no
`--settings` hook (the hook is a host binary; in a pod the microVM is the
boundary, and `--allowedTools`/`--disallowedTools` remain). An adapter for a pod
run must therefore accept `--mcp-config` as either a path or a JSON document.

The first two flags are a **security property**, not a convenience: they stop
the agent from loading hooks, MCP servers and instructions from the directory
it is working on (or from the operator's own user-scope settings), so the
repository under examination cannot add unmediated tools next to the ones
nucleus installed. Nucleus appends them after your `AGENT_ARGS`, so an argument
you pass cannot be the last word on them.

### An agent CLI that speaks the protocol natively

Claude Code accepts every flag above as-is:

```bash
nucleus run   --agent claude --local --unsandboxed "fix the failing test"
nucleus shell --agent claude --unsandboxed --profile codegen --dir ~/repo
```

It refuses to start inside one of its own sessions. To try `nucleus shell` from
inside one, unset its session variable for the nested launch:

```bash
env -u CLAUDECODE nucleus shell --agent claude --unsandboxed
```

### An agent CLI that does not

Point `--agent` at a small adapter program that translates the protocol into
your agent's own flags and then `exec`s the agent. An adapter MUST preserve the
confinement: whatever your agent's equivalent of "load no project or user
settings, and no MCP servers except the ones given" is, it has to be on the
agent's command line, or the working directory can configure the agent nucleus
is mediating. An adapter that drops it drops the boundary.
