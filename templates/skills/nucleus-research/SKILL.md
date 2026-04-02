---
name: nucleus-research
description: Switch to the research compartment (read-only exploration)
---

# Switch to Research Compartment

Switch the active Nucleus compartment to **research**.

Research compartment allows read-only exploration: file reading, glob/grep search, and web fetch are permitted. File writes, shell commands, and git operations are blocked.

## Usage

Run this command to switch:

```bash
nucleus-claude-hook --compartment research
```

After switching, your capabilities will be restricted to read-only operations until you switch to a different compartment.
