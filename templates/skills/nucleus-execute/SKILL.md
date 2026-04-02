---
name: nucleus-execute
description: Switch to the execute compartment (full execution access)
---

# Switch to Execute Compartment

Switch the active Nucleus compartment to **execute**.

Execute compartment enables shell commands, git commit, and full build/test/deploy capabilities. Use this when you need to run commands, build, or test.

## Usage

Run this command to switch:

```bash
nucleus-claude-hook --compartment execute
```

After switching, you can run bash commands, git operations, and other execution tasks. Note: escalation from research directly to execute is blocked -- you must go through draft first.
