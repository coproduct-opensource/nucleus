---
name: nucleus-status
description: Show current Nucleus security status and active compartment
---

# Nucleus Security Status

Display the current Nucleus security posture: active compartment, profile, session info, and any taint state.

## Usage

Run this command to see the current status:

```bash
nucleus-claude-hook --status
```

For machine-readable JSON output:

```bash
nucleus-claude-hook --status --json
```

This shows:
- Active compartment (research/draft/execute/breakglass)
- Security profile in effect
- Session taint state
- Operation counts
