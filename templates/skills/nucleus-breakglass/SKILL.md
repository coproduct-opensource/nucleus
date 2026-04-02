---
name: nucleus-breakglass
description: Emergency breakglass -- unlock all capabilities with a reason
---

# Emergency Breakglass

Switch to **breakglass** compartment, unlocking all capabilities. Requires a justification reason.

Breakglass is for emergencies only (e.g., production outage). All actions are audited. You must provide a reason -- bare breakglass without justification is denied.

## Usage

Run this command with your reason as $ARGUMENTS:

```bash
nucleus-claude-hook --compartment "breakglass:$ARGUMENTS"
```

The reason is recorded in the audit trail. Escalation rules still apply -- you must be in the execute compartment to escalate to breakglass.
