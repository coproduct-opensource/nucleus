---
name: nucleus-draft
description: Switch to the draft compartment (read + write, no execution)
---

# Switch to Draft Compartment

Switch the active Nucleus compartment to **draft**.

Draft compartment allows file reads and writes (low-risk edits) but blocks shell command execution, git push, and web access. Use this when writing or editing code.

## Usage

Run this command to switch:

```bash
nucleus-claude-hook --compartment draft
```

After switching, you can read and write files but cannot run bash commands or access the web.
