---
name: airlock
description: Transition between security compartments (research, draft, exec, breach)
---

The user wants to change their security compartment.

Parse the argument and write a transition request file. **Do NOT run any CLI commands.**
Write the JSON to `.nucleus/transition-request.json`:

- "research" or "seal" -> `{"target": "research", "reason": "user requested seal/research"}`
- "draft" -> `{"target": "draft", "reason": "user requested draft mode"}`
- "exec" or "execute" -> `{"target": "execute", "reason": "user requested execute mode"}`
- "breach" followed by a reason -> `{"target": "breakglass:REASON", "reason": "REASON"}`

The transition will be validated and applied by the nucleus hook on the next tool
invocation. The hook enforces single-step escalation (research -> draft -> execute ->
breakglass) and will deny skip-level transitions.

After writing the file, confirm: "Airlock transition to [compartment] requested. Will take effect on next tool call."

If "breach" is requested without a reason, ask for one -- it is required.
