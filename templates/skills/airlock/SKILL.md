---
name: airlock
description: Transition between security compartments (research, draft, exec, breach)
---

The user wants to change their security compartment.

Parse the argument:
- "research" or "seal" → `nucleus-claude-hook --compartment research`
- "draft" → `nucleus-claude-hook --compartment draft`
- "exec" or "execute" → `nucleus-claude-hook --compartment execute`
- "breach" followed by a reason → `nucleus-claude-hook --compartment "breakglass:REASON"`

After switching, confirm: "Airlock cycled to [compartment]. [capabilities summary]."

If "breach" is requested without a reason, ask for one — it's required.
