---
name: nucleus-promote
description: Promote AI-generated content to human-verified status
---

# Promote Content

Mark AI-generated content as human-verified. This updates the provenance metadata so downstream consumers know a human has reviewed and approved the output.

## Usage

After reviewing AI-generated content, run:

```bash
nucleus-claude-hook --reset-session "$ARGUMENTS"
```

This clears the taint flag on the specified session, indicating human review is complete. The receipt chain is preserved for audit -- only the taint state is cleared.

Provide the session ID as $ARGUMENTS. To find the current session ID, use `/nucleus-status`.
