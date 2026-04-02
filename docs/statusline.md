# Nucleus Status Line for Claude Code

The `--statusline` flag outputs a compact, single-line summary of the current
Nucleus security posture. It is designed for integration with Claude Code's
[status line feature](https://code.claude.com/docs/en/statusline).

## Setup

Add the following to your `.claude/settings.json`:

```json
{
  "statusLine": "nucleus-claude-hook --statusline"
}
```

If `nucleus-claude-hook` is not on your `PATH`, use the full path:

```json
{
  "statusLine": "/path/to/nucleus-claude-hook --statusline"
}
```

### Shell script fallback

A lightweight shell script is also available at `scripts/nucleus-statusline.sh`.
It reads environment variables and counts session files, but does not parse
session state (no taint or flow detection). Use it only when the Rust binary
is unavailable:

```json
{
  "statusLine": "bash /path/to/nucleus/scripts/nucleus-statusline.sh"
}
```

## Output format

```
<compartment> | <profile> | flow:<yes|no> | <clean|tainted> | <N> ops
```

Example outputs:

```
default | safe_pr_fixer | flow:no | clean | 0 ops
research | read_only | flow:yes | tainted | 42 ops
draft | fix_issue | flow:yes | clean | 17 ops
```

### Fields

| Field       | Description                                              |
|-------------|----------------------------------------------------------|
| compartment | Active compartment name (`NUCLEUS_COMPARTMENT` or config)|
| profile     | Active profile (`NUCLEUS_PROFILE` or config default)     |
| flow        | Whether the flow graph has any observations              |
| taint       | `clean` or `tainted` (web content detected in flow)      |
| ops         | Total operations (allowed + denied) across all sessions  |

## How it works

The Rust implementation (`--statusline`) calls the same `collect_status()`
function used by `--status`, then formats the result into a single line.
It reads real session state from `~/.local/share/nucleus/sessions/`, so the
taint and operation counts reflect actual hook activity.

The shell script fallback only reads environment variables and counts session
files on disk -- it cannot detect taint or flow status.
