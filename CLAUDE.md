# Nucleus - Claude Code Guidelines

## Project Identity

Nucleus is an **open source, vendor-agnostic** secure execution runtime for AI agents.

**License**: MIT
**Repository**: Public (github.com/coproduct-opensource/nucleus)

## Vendor Neutrality Rules

### NEVER include in nucleus:
- Anthropic/Claude-specific code or references
- OpenAI-specific code or references
- Any LLM vendor names, SDKs, or APIs
- Vendor-specific credential formats (Claude OAuth, OpenAI API keys)
- Vendor-specific cost models or pricing

### DO include:
- Generic credential passing (`credentials.env` with arbitrary key-value pairs)
- Work-type based policies (codegen, review, research) not LLM-specific
- Generic budget models (cost per second, max USD) without vendor rates
- Standard protocols (gRPC, SPIFFE, mTLS)

### Examples

**Bad** (vendor-specific):
```rust
pub struct CredentialsSpec {
    pub claude_oauth_token: Option<String>,  // NO - vendor specific
    pub anthropic_api_key: Option<String>,   // NO - vendor specific
}
```

**Good** (vendor-agnostic):
```rust
pub struct CredentialsSpec {
    pub env: BTreeMap<String, String>,  // Generic env vars
    pub secret_ref: Option<String>,      // Reference to external secret
}
```

**Bad** (vendor-specific documentation):
```yaml
# Pass your Claude API key
credentials:
  claude_api_key: "sk-ant-..."
```

**Good** (vendor-agnostic documentation):
```yaml
# Pass credentials as environment variables
credentials:
  env:
    LLM_API_TOKEN: "your-token-here"
```

## Architecture

Nucleus provides:
1. **Isolation**: Firecracker microVMs with network/filesystem sandboxing
2. **Policy**: Permission lattice (read/write/exec/network capabilities)
3. **Identity**: SPIFFE workload identity for pods
4. **Observability**: Structured logging, audit trails

Nucleus does NOT provide:
1. LLM API integration (that's the orchestrator's job)
2. Vendor-specific credential management
3. AI-specific prompt handling

## Integration Pattern

Orchestrators handle vendor-specific concerns and translate to nucleus's generic interface:

```
Orchestrator (vendor-aware)          Nucleus (vendor-agnostic)
┌────────────────────────────┐       ┌────────────────────────────┐
│ Claude OAuth extraction    │       │ PodSpec with generic:      │
│ Anthropic rate limits      │  ──►  │   - credentials.env        │
│ Claude Code SDK            │       │   - policy profiles        │
│ Vendor cost tracking       │       │   - resource limits        │
└────────────────────────────┘       └────────────────────────────┘
```

## Testing

When writing tests, use generic placeholders:
- `LLM_API_TOKEN` not `ANTHROPIC_API_KEY`
- `test-token-123` not `sk-ant-...`
- Policy names like `codegen`, `review` not `claude_coding`

## Documentation

All documentation should:
- Use "LLM" or "AI agent" not specific vendor names
- Show generic credential examples
- Reference the orchestrator layer for vendor integration
