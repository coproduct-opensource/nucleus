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

The first two flags are a **security property**, not a convenience: they stop
the agent from loading hooks, MCP servers and instructions from the directory
it is working on (or from the operator's own user-scope settings), so the
repository under examination cannot add unmediated tools next to the ones
nucleus installed. Nucleus appends them after your `AGENT_ARGS`, so an argument
you pass cannot be the last word on them.

### An agent CLI that speaks the protocol natively

Claude Code accepts every flag above as-is:

```bash
nucleus run   --agent claude --local "fix the failing test"
nucleus shell --agent claude --profile codegen --dir ~/repo
```

It refuses to start inside one of its own sessions. To try `nucleus shell` from
inside one, unset its session variable for the nested launch:

```bash
env -u CLAUDECODE nucleus shell --agent claude
```

### An agent CLI that does not

Point `--agent` at a small adapter program that translates the protocol into
your agent's own flags and then `exec`s the agent. An adapter MUST preserve the
confinement: whatever your agent's equivalent of "load no project or user
settings, and no MCP servers except the ones given" is, it has to be on the
agent's command line, or the working directory can configure the agent nucleus
is mediating. An adapter that drops it drops the boundary.
