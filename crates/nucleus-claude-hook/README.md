# nucleus-claude-hook

A [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) for AI coding assistants that enforces the Nucleus permission kernel on every tool call.

## Quick Start

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-claude-hook
nucleus-claude-hook --setup
# Restart your AI coding assistant -- the hook is now active
```

## What It Does

Every tool call flows through the Nucleus permission kernel before execution. The hook:

- **Tracks information flow** -- knows what data entered your session and from where
- **Blocks dangerous combinations** -- e.g., writing code based on untrusted web content (the core prompt injection vector)
- **Manages compartments** -- Research/Draft/Execute/Breakglass transitions with taint clearing
- **Signs receipts** -- Ed25519-signed receipt chain for every decision
- **Enforces provenance** -- optional schema-driven deterministic data extraction with witness bundles

## Diagnostics

```bash
nucleus-claude-hook --smoke-test   # verify it works
nucleus-claude-hook --doctor       # diagnose issues
nucleus-claude-hook --version      # check installed version
```

## Configuration

The hook loads configuration from `~/.nucleus/` and project-level `.nucleus/` directories:

- **Profiles** -- Named permission sets (codegen, code_review, safe_pr_fixer, etc.)
- **Compartment tokens** -- Control session transitions between security contexts
- **Provenance schemas** -- `.provenance.json` files declaring field derivation methodology
- **Delegation ceilings** -- Permission bounds inherited from parent sessions

## Architecture

The hook is organized into extracted modules:

| Module | Purpose |
|--------|---------|
| `protocol` | Hook I/O parsing (JSON stdin/stdout) |
| `classify` | Tool call classification and IFC labeling |
| `session` | Session state, witness bundles, provenance output |
| `config` | Profile resolution, config file loading |
| `config_provenance` | Config source tracking (user-local vs repo-supplied) |
| `context` | Provenance context injection into prompts |
| `receipts` | Ed25519 receipt chain with execution context |
| `integrity` | Binary self-integrity verification at startup |
| `url_policy` | Covert channel detection in URLs |
| `c2pa_output` | C2PA sidecar emission (feature-gated) |
| `status` | Status line display |

## Feature Flags

| Feature | Purpose |
|---------|---------|
| `wasm-sandbox` | Enable WASM parser execution for deterministic field extraction |
| `c2pa` | Enable C2PA content credential sidecar emission at SessionEnd |

See [`docs/quickstart-hook.md`](../../docs/quickstart-hook.md) for the full guide.
