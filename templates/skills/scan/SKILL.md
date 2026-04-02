---
name: scan
description: Security status check — compartment, taint, profile, recent decisions
---

Run a security status scan.

`nucleus-claude-hook --status --json`

Parse the JSON and present: compartment, profile, taint status (clean/tainted), operation count, recent denials.
