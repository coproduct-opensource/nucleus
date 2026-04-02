#!/bin/bash
# Nucleus status line for Claude Code
#
# Lightweight shell fallback that outputs a compact status string.
# Prefer `nucleus-claude-hook --statusline` (Rust) when the binary is
# installed — it reads real session state from disk.
#
# Usage in .claude/settings.json:
#   { "statusLine": "nucleus-claude-hook --statusline" }
#
# Or, if the binary is not on PATH:
#   { "statusLine": "bash /path/to/scripts/nucleus-statusline.sh" }

set -euo pipefail

PROFILE="${NUCLEUS_PROFILE:-safe_pr_fixer}"
COMPARTMENT="${NUCLEUS_COMPARTMENT:-default}"

# Count active sessions on disk.
SESSION_DIR="${HOME}/.local/share/nucleus/sessions"
if [ -d "$SESSION_DIR" ]; then
    SESSION_COUNT=$(find "$SESSION_DIR" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
else
    SESSION_COUNT=0
fi

# Check for .nucleus/ project config in cwd.
if [ -d ".nucleus" ]; then
    CONFIG="yes"
else
    CONFIG="no"
fi

echo "${COMPARTMENT} | ${PROFILE} | config:${CONFIG} | sessions:${SESSION_COUNT}"
