# Nucleus Sandbox — Behavioral Rules

When the nucleus plugin is active, all file, command, and network operations
MUST be routed through nucleus tools. These rules ensure the agent never
bypasses VM isolation.

## File Operations

1. **Always use `nucleus_read`** to read files. Never use built-in file-read
   tools when nucleus is available.
2. **Always use `nucleus_write`** to write or create files. Never use built-in
   write tools when nucleus is available.
3. **Always use `nucleus_glob`** to search for files by pattern. Never use
   built-in glob/find tools when nucleus is available.
4. **Always use `nucleus_grep`** to search file contents. Never use built-in
   grep tools when nucleus is available.

## Command Execution

5. **Always use `nucleus_run`** to execute commands. Never use built-in bash
   or shell tools when nucleus is available.
6. **Pass commands as argument arrays**, not shell strings. For example, use
   `["git", "status"]` instead of `"git status"`. This prevents shell
   injection.
7. **Check exit codes** in the response. A `success: false` result means the
   command failed — read `stderr` for diagnostics before retrying.

## Network Operations

8. **Always use `nucleus_web_fetch`** for HTTP requests. Never use built-in
   fetch tools when nucleus is available.
9. **Always use `nucleus_web_search`** for web searches. Never use built-in
   search tools when nucleus is available.
10. **Respect network allowlists.** If a fetch or search returns a policy
    error, do not attempt to bypass it. Inform the user that the URL or
    domain is not in the network allowlist.

## Approval Flow

11. **Request approval before destructive operations.** If a write, run, or
    delete operation is denied with an approval-required error, use
    `nucleus_approve` to request pre-approval, then retry.
12. **Never retry denied operations without approval.** If an operation
    returns a policy denial (not an approval-required error), it is
    permanently denied by policy. Do not retry.
13. **Approvals are scoped and time-limited.** Each approval covers a specific
    operation and expires after the configured TTL (default 300 seconds).

## General

14. **Never attempt to access the filesystem or network outside nucleus.**
    The sandbox boundary is the security perimeter. Any bypass attempt would
    be logged and flagged.
15. **Prefer `nucleus_glob` + `nucleus_read` over `nucleus_run` for file
    discovery.** Glob and read are cheaper and more auditable than running
    `find` or `cat` via the command executor.
