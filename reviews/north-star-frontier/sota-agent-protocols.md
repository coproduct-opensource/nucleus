# State of the art (2025–2026): agent identity, protocol-level authorization, agent payments

Research memo for the Nucleus North-Star exercise. Date: 2026-09-08. Static web research; primary specs fetched where the egress proxy allowed (MCP spec text via GitHub raw, A2A spec via GitHub raw, Claude Code / Agent SDK docs, MCP blog, Gemini CLI policy-engine doc, kubernetes-sigs/agent-sandbox README). IETF datatracker, ap2-protocol.org, developers.openai.com, stripe.com, learn.microsoft.com and blog.cloudflare.com were blocked; those are covered through secondary sources and are flagged as such.

The organizing question for every system below is the same four-part one: **how is the human's authorization represented, how is it scoped, how is it delegated, how is it verified — and is enforcement structural (a component that cannot be argued with) or advisory (a hint the agent or a client is expected to honor)?**

---

## 1. Protocol-level authorization

### 1.1 MCP authorization (2025-06-18 → 2025-11-25 → 2026-07-28)

**Representation.** MCP treats the MCP server as an OAuth 2.1 *resource server* and the client as an OAuth client acting for the resource owner. Authorization is an OAuth access token; the human's consent is whatever the authorization server's consent screen captured. Required building blocks: RFC 9728 Protected Resource Metadata (server advertises its AS), RFC 8414 AS metadata, RFC 8707 Resource Indicators ("MUST include the `resource` parameter in both authorization requests and token requests" naming the canonical MCP server URI), PKCE, and Client ID Metadata Documents (HTTPS URL as `client_id`) which the 2026-07-28 revision promotes over Dynamic Client Registration.

**Scoping.** Scopes only. Servers "SHOULD include a `scope` parameter in the `WWW-Authenticate` header" on 401/403 and clients "SHOULD respond ... by requesting a new access token with an increased set of scopes" (step-up). SEP-2350 clarifies scope accumulation. There is no per-tool, per-argument, per-amount or time-bounded grant in the core protocol; fine-grained authorization *inside* a server is explicitly out of scope.

**Delegation.** Two hard rules: "MCP servers MUST NOT pass through the token it received from the MCP client" and "MUST only accept tokens specifically intended for themselves" (audience binding). Downstream delegation therefore requires the server to run its own OAuth client (URL-mode elicitation, "essential for auth flows, payment processing", explicitly "not for authorizing the MCP client's access to the MCP server"). The Enterprise-Managed Authorization extension (stable June 2026, `io.modelcontextprotocol/enterprise-managed-authorization`) uses ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant, RFC 8693 token exchange) so the IdP asserts *user + groups/roles + target resource* and the MCP server's AS mints a token without a consent screen. Adopters: Okta (Cross App Access), Anthropic clients, VS Code; Asana, Atlassian, Canva, Figma, Linear, Supabase, Slack as servers. It asserts users, not agents; agent-vs-user identity, fine-grained authz and audit are not covered.

**Verification / audit.** RFC 9207 `iss` validation (SEP-2468) against mix-up attacks; W3C trace-context propagation replaces protocol sessions in 2026-07-28. Audit is a SHOULD on clients ("maintain audit logs of tool usage"); nothing signed, nothing portable.

**Tool annotations and human-in-the-loop are advisory.** `readOnlyHint`, `destructiveHint` (default true), `idempotentHint`, `openWorldHint` exist, but "clients MUST consider tool annotations to be untrusted unless they come from trusted servers" and "there SHOULD always be a human in the loop with the ability to deny tool invocations." The MCP maintainers' own March 2026 post is blunt: "If you need a guarantee that a tool can't exfiltrate data, that's a job for network controls or sandboxing, not a boolean hint." Clients (Claude Code, Codex) use annotations to drive approval UX and policy-engine rules; enforcement is in the client, not the protocol.

**Verdict.** Structural at the *token audience* layer (RFC 8707/9728 make a token useless elsewhere); advisory at the *action* layer. Authorization granularity stops at OAuth scope strings.

### 1.2 A2A v1.0 (Linux Foundation, 2026; 1.0.1 May 2026)

**Representation.** Agent Cards at `/.well-known/agent-card.json` declare `securitySchemes` (API key, HTTP, OAuth2, OIDC, mTLS) OpenAPI-style; **Signed Agent Cards** (JWS over RFC 8785 canonical JSON, `alg`/`typ`/`kid`, keys via `jku`) prove the card's *metadata* is authentic. "Identity information is handled at the protocol layer, not within A2A semantics."

**Scoping / delegation.** Mid-task the server can move to `TASK_STATE_AUTH_REQUIRED`; the client may fulfil out-of-band or "delegate the authorization request to their own client (forming chains)". The spec "does not define credential scope, representation, validity, or revocation" and states "Agents MUST NOT treat the `TASK_STATE_AUTH_REQUIRED` state transition, by itself, as authorization for any particular operation." Extensions (URI-identified, `required` flag, `A2A-Extensions` header) are the escape hatch; official examples: Secure Passport, Timestamp, Traceability, Agent Gateway Protocol. Nucleus already publishes two such extensions (`.../ext/receipt/v1`, `.../ext/runtime-guarantees/v1`).

**Verification / audit.** Servers must scope task listing to the authenticated client and not leak existence; no normative audit. Push-notification webhooks carry `AuthenticationInfo{scheme, credentials}`.

**Verdict.** Discovery and card integrity are structural; authorization, delegation semantics and audit are entirely implementation-defined. A2A is a transport for authority claims, not a definition of them.

---

## 2. Agent identity

### 2.1 IETF: WIMSE applicability (draft-ni-wimse-ai-agent-identity-02) and AIMS (draft-klrc-aiagent-auth-03)

WIMSE's agent draft asks for automated short-lived credentials, "task-oriented, fine-grained access tokens with short validity periods", and "explicit workflow management ... the call context must always be visible and preserved." AIMS (authors from DeFakto, AWS, Ping, Zscaler; later OpenAI and Okta) is a *framework*, not a protocol: it recommends SPIFFE / WIMSE identifiers for agent workloads, OAuth for delegation and continuous evaluation of identity and permissions. Delegation is represented with RFC 8693 `act`/`sub` claims. **Transaction Tokens for Agents** (draft-oauth-transaction-tokens-for-agents-06) extend Txn-Tokens so the `act` field identifies the agent and `sub` the principal; systems "MUST maintain audit trails of AI agent activities" and "MUST validate tokens at trust domain boundaries." **Attenuating agent tokens** (draft-niyikiza) express delegation as "a cryptographically sealed chain that can only narrow authority and is verifiable offline"; the OAuth on-behalf-of draft adds `requested_actor` / `actor_token`. Nucleus's own gap analysis (`docs/wimse-aims-conformance-gap.md`) already tracks `typ=at+jwt`, `client_id`, `scope`, `act` as open violations.

**Verdict.** Identity layer is converging on SPIFFE/WIMSE + JWT with `act` chains; enforcement is wherever the token is validated. None of these drafts touch *what the agent may do with a syscall, file or network socket*.

### 2.2 Vendor IdPs and gateways

- **Microsoft Entra Agent ID** (GA with Agent 365, May 2026): every agent identity derives from an *agent identity blueprint*; policies (Conditional Access, risk-based blocking) attach at blueprint level and "cover only the agent identity, not the agent's user account." Agent Registry distinguishes "classic" service principals from "modern" blueprint-backed agents with "full audit trail." Sponsors/owners give accountability. Structural at sign-in, advisory beyond the token.
- **Okta / Auth0 for AI Agents** (May 2026): Token Vault stores third-party tokens and does RFC 8693 on-behalf-of exchange; "Agent as Principal", Auth for MCP, CIBA-style async approval for human-in-the-loop, FGA permissions index. Structural at token issuance; per-action enforcement delegated to the resource.
- **Cloudflare MCP Server Portals** (Aug 2026 Gateway update): TLS-inspected traffic is classified via `Mcp-Protocol-Version`, `Mcp-Method` (`tools/call`), `Mcp-Name`; a boolean policy selector blocks MCP calls that bypass an approved portal; each upstream is behind Access (managed OAuth / OIDC); service tokens for autonomous agents; dashboards for per-user, per-server call counts. This is the closest thing to *network-structural* enforcement of MCP, but it sees tool names, not effects.
- **Kubernetes Agent Sandbox (kubernetes-sigs, beta v0.1.x, Apache-2.0):** CRDs `Sandbox`, `SandboxTemplate`, `SandboxClaim`, `SandboxWarmPool`; isolation delegated to gVisor / Kata via `runtimeClassName`; stable hostname, persistent storage, pause/resume, scheduled deletion; a threat-model document exists. It provides *containment* and lifecycle, but no authorization vocabulary, no receipts, no per-effect policy.

---

## 3. Coding-agent permission models (the de-facto enforcement points today)

| System | Representation of authorization | Structural? |
|---|---|---|
| **Claude Code / Agent SDK** | Modes (`default`, `acceptEdits`, `plan`, `dontAsk`, `bypassPermissions`, `auto`); `allow/ask/deny` rules with fixed precedence "deny, then ask, then allow"; six-step SDK order hooks → deny → ask → mode → allow → `canUseTool`. "Permission rules are enforced by Claude Code, not by the model." Deny rules "block in every mode, including `bypassPermissions`." Protected/critical paths never auto-approved. `auto` mode: a separate classifier model that sees prompts, tool calls and CLAUDE.md but "tool results are stripped"; conversational boundaries are re-read from transcript and can be lost to compaction — docs say "For a hard guarantee, add a deny rule." Bash sandbox: Seatbelt / bubblewrap + optional seccomp, domain allowlist via proxy, credential *masking* with sentinel substitution and SigV4 re-signing at the proxy; "the operating system enforces that boundary for every Bash command and its child processes." Escape hatch: the *unsandboxed retry* unless `allowUnsandboxedCommands:false`. Managed settings can pin filesystem isolation. | Rules + sandbox: structural (process-local). Classifier: advisory-by-construction (probabilistic). Read/Edit deny rules "don't apply to arbitrary subprocesses." |
| **OpenAI Codex CLI** | Two dials: `sandbox_mode` (`read-only`, `workspace-write`, `danger-full-access`) and `approval_policy` (`untrusted`, `on-request`, `on-failure`, `never`); network off by default under workspace-write; OS enforcement via Seatbelt (macOS), bubblewrap+Landlock+seccomp (Linux), restricted tokens (Windows). Known issue: `network_access=true` silently ignored by seatbelt profile (#10390). | Structural for sandboxed commands; approved escalations run outside. |
| **Gemini CLI** | TOML policy engine, decisions `allow`/`deny`/`ask_user`; five priority tiers (default 1 < extension 2 < workspace 3 (disabled) < user 4 < admin 5) with `final_priority = tier_base + toml_priority/1000`; `argsPattern` regex over JSON args, `commandPrefix`, `mcpName`, `toolAnnotations` matching; admin policies in OS-owned dirs with ownership checks; Trusted Folders disable workspace config. Reported bypass: place a script named after an approved tool earlier on `$PATH`. | Structural for tool dispatch; weak against the shell itself. |

**Common shape.** All three converge on: (a) a small totally-ordered decision lattice (deny > ask > allow), (b) precedence by *source* (admin/managed > user > project), (c) an OS sandbox as the only layer that survives a hostile model, (d) hooks/callbacks as the extension point (`PreToolUse` returning `permissionDecision`, `updatedInput`; Gemini `ask_user`; Codex approval prompts), and (e) an explicit admission that the model-facing layer is advisory. None emits a signed, third-party-verifiable record of what was authorized versus what happened.

---

## 4. Agent payments: the most mature *representation* of human authorization

- **Google AP2** (Sept 2025; 60+ partners; layered as an A2A/MCP extension): three chained **mandates** as Verifiable Digital Credentials. *Intent Mandate* — natural-language prompt playback, payer/payee, allowed payment methods, risk payload, TTL; *Cart Mandate* — exact cart at exact price, "the user cryptographically signs ... using a hardware-backed device key" in human-present flows, agent-key signed in human-not-present flows within the intent's constraints; *Payment Mandate* — derived credential the network sees. This is the cleanest published model of *scoped, time-bounded, principal-signed delegation with an offline-verifiable audit trail*. Nucleus already models a Cart Mandate as `ApprovalBundle{manifest_hash = cart hash}` (`crates/nucleus-recompute/src/cart.rs`, `crates/nucleus-identity/tests/cart_mandate.rs`).
- **OpenAI/Stripe Agentic Commerce Protocol** (spec 2026-04-17; Meta co-maintainer): Checkout API, **Delegated Payment Spec** (`POST /agentic_commerce/delegate_payment`, signed request header, idempotency key), product feeds. Stripe's *Shared Payment Token* is scoped to "one seller profile, one currency, one maximum amount, and one expiration timestamp", single-use, minutes-lived; "the cap is set at issuance and cannot grow afterward." Authorization is *attenuation at the issuer*, structurally enforced by the PSP.
- **Mastercard Agent Pay** (Apr 2025): *Agentic Tokens* (MDES extension) "bind a tokenized card credential to a specific agent, a specific merchant scope, and a specific consent policy"; in production in Singapore/Malaysia; will expose AP2 Intent/Cart mandates in the provisioning API.
- **Visa Intelligent Commerce + Trusted Agent Protocol** (Oct 2025, with Cloudflare): TAP signs agent identity into HTTP requests via RFC 9421 HTTP Message Signatures on the Web Bot Auth base, Ed25519 keys in a Visa-operated directory; carries intent-to-buy, consumer-recognition and payment info; integrated into OpenAI surfaces June 2026. Structural at the merchant edge (signature verifies or not), but only identifies the *agent*, not what the *human* authorized.

**Verdict.** Payments are ahead of the rest of the stack on clauses (3) and (4): authorization objects are signed by the principal, carry amount/merchant/time bounds, are single-use or attenuating, and the enforcing party (network, PSP) is not the agent. The lesson generalizes: the enforcement point must be *outside* the agent and must consume a *signed, bounded, principal-issued object*, not a scope string.

---

## 5. Cross-cutting findings against the North Star

1. **Structural enforcement exists only at three layers today:** token audience (RFC 8707/9728, ID-JAG, SPT), OS sandbox (Seatbelt/bubblewrap/Landlock/gVisor/Kata), and payment-network attenuation (SPT, Agentic Tokens). Everything in between — tool annotations, classifier verdicts, A2A auth-required, IdP conditional access — is advisory or coarse.
2. **No common authorization object.** OAuth scopes (MCP/EMA), TOML rules (Gemini), JSON rule strings (Claude), mandates/VCs (AP2), allowances (ACP), Agentic Tokens (Mastercard) do not compose. Delegation chains (`act` claims, attenuating tokens) are being standardized in IETF but are not yet consumed by any coding-agent runtime.
3. **Audit is unsigned and local** everywhere except AP2 mandates, TAP signatures and (partly) Entra's registry. No system produces a receipt binding *authorization object → mediated effect → outcome* that a third party can verify offline.
4. **Escape hatches are the norm:** unsandboxed retry, `danger-full-access`, `bypassPermissions`, PATH shadowing, hooks executing "with the session's permissions", annotations from untrusted servers, workspace-tier policies silently disabled.
5. **Identity is solved for the user, half-solved for the agent.** ID-JAG/EMA carries the *user*; Entra/Auth0 carry the *agent*; nobody carries *both plus the per-call task context* to the effect boundary — which is exactly what WIMSE's "call context must always be visible and preserved" demands.

---

## 6. Interfaces a vendor-agnostic runtime must expose to sit beneath all of these

To be the enforcement point rather than one more advisory layer, Nucleus should expose the following, all vendor-neutral:

1. **Authorization-object ingress (`Grant`).** Accept, verify and *intersect* signed authority from any of: OAuth access token (RFC 8707 audience, scope), ID-JAG/EMA assertions, RFC 8693 `act`-chained transaction tokens, attenuating delegation tokens, AP2 Intent/Cart Mandates (VDC), ACP delegated-payment allowances, Mastercard/Visa agentic tokens, and Claude/Codex/Gemini rule files. Normalize to one lattice element (Portcullis-style capability levels + budgets + TTL + principal chain) that can only be narrowed. This is clause (3).
2. **Effect-boundary mediation with typed effect vocabulary.** Every side effect (file, exec, socket/egress, tool call, payment, message send) crosses a mediated channel that consumes a `Grant` and denies by default — the MCP maintainers' "network controls or sandboxing" made concrete. Expose it as: a PreToolUse-compatible hook endpoint (allow/deny/ask/`updatedInput`), an MCP-aware proxy (`Mcp-Method`, `Mcp-Name`, tool annotations as *inputs* not authority), an A2A-compatible `AUTH_REQUIRED` responder, and an egress proxy with credential masking/injection (the pattern Claude Code's sandbox proxy and Auth0 Token Vault both use). Clause (4).
3. **Principal-approval channel (`Escalate`).** A single widening path taking a signed approval from a *different* key than the workload (device key, IdP-issued CIBA result, elicitation URL-mode completion), bounded by the delegation ceiling — the Cart-Mandate pattern generalized to any effect. Expose CIBA/elicitation-URL adapters so any client (Claude, Codex, Gemini, ChatGPT) can drive it.
4. **Workload identity emission.** Per-pod SPIFFE/WIMSE SVIDs; JWTs with `typ=at+jwt`, `client_id`, `scope`, `act` chain; signed A2A Agent Cards with the runtime-guarantees extension; RFC 9421 HTTP Message Signatures (Web Bot Auth / TAP) on outbound requests so merchants and gateways can attribute traffic to the pod, not the model. Clause (1): identity is of the *runtime*, independent of vendor.
5. **Signed receipts and transparency.** For every mediated effect emit an offline-verifiable receipt binding (`Grant` hash, effect descriptor, outcome, pod attestation, time) — the A2A receipt extension generalized — and publish to a transparency log so AP2 mandates, MCP audit SHOULDs, Entra registries and Cloudflare dashboards can all reference one immutable record. Clause (4)+(5).
6. **Machine-checked policy artifacts.** Publish the lattice semantics (deny > ask > allow, source precedence, monotone narrowing, no self-widening) as verified theorems and ship conformance harnesses (Kani/Lean) that vendors' rule files are compiled *into*, so "structurally incapable" is a proof about the runtime rather than a property of each client. Clause (4).
7. **Frontier metrics API.** Expose the *safely-delegatable envelope* as data: for each effect type, the maximal `Grant` the runtime can enforce, the count of mediated vs. escaped effects, false-deny/false-allow rates from adversarial corpora (envelope-adversarial-corpus, adversary-probe), and payment-allowance utilization. Ratchet these over releases. Clause (5).

The one-line synthesis: **the industry has standardized how to *name* the principal (ID-JAG, Entra, SPIFFE) and how to *bound a payment* (mandates, SPTs), but not how to bound an arbitrary effect. A vendor-agnostic runtime wins by being the place where any of those authority objects is intersected into one monotone grant, enforced at the syscall/socket/tool boundary, and receipted.**

---

## Sources

Primary (fetched):
- MCP authorization spec (2025-11-25 text): https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/basic/authorization.mdx
- MCP tools / annotations (draft): https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/draft/server/tools.mdx
- MCP elicitation (draft): https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/draft/client/elicitation.mdx
- MCP 2026-07-28 release candidate: https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
- MCP tool annotations as risk vocabulary: https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/
- MCP Enterprise-Managed Authorization: https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/ and https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization
- A2A v1.0 specification: https://github.com/a2aproject/A2A/blob/main/docs/specification.md (mirror: https://a2a-protocol.org/latest/specification/)
- AP2 repository: https://github.com/google-agentic-commerce/AP2 (spec: https://ap2-protocol.org/specification/)
- Agentic Commerce Protocol repository: https://github.com/agentic-commerce-protocol/agentic-commerce-protocol ; Delegated Payment Spec: https://developers.openai.com/commerce/specs/payment
- Claude Code permissions: https://code.claude.com/docs/en/permissions ; permission modes: https://code.claude.com/docs/en/permission-modes ; hooks: https://code.claude.com/docs/en/hooks ; sandboxing: https://code.claude.com/docs/en/sandboxing ; Agent SDK permissions: https://code.claude.com/docs/en/agent-sdk/permissions
- Gemini CLI policy engine: https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md
- Kubernetes Agent Sandbox: https://github.com/kubernetes-sigs/agent-sandbox ; https://agent-sandbox.sigs.k8s.io/
- agentgateway ID-JAG issue: https://github.com/agentgateway/agentgateway/issues/2029
- Nucleus internal: docs/wimse-aims-conformance-gap.md, docs/a2a-receipt-extension.md, docs/a2a-runtime-guarantees-extension.md, crates/nucleus-recompute/src/cart.rs

IETF drafts (datatracker blocked; cited via secondary summaries):
- WIMSE applicability for AI agents: https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/
- AIMS / AI Agent Authentication and Authorization: https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/
- Identity Assertion Authorization Grant (ID-JAG): https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant
- Transaction Tokens for Agents: https://datatracker.ietf.org/doc/draft-oauth-transaction-tokens-for-agents/
- Attenuating agent tokens: https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/
- OAuth on-behalf-of user for AI agents: https://www.ietf.org/archive/id/draft-oauth-ai-agents-on-behalf-of-user-02.txt

Secondary:
- Codex approvals & security: https://developers.openai.com/codex/agent-approvals-security ; sandbox concepts: https://developers.openai.com/codex/concepts/sandboxing ; seatbelt network bug: https://github.com/openai/codex/issues/10390
- Entra Agent ID: https://learn.microsoft.com/en-us/entra/agent-id/agent-identities ; blueprints: https://learn.microsoft.com/en-us/entra/agent-id/agent-blueprint ; Conditional Access for agents: https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id
- Auth0 Token Vault: https://auth0.com/blog/auth0-token-vault-secure-token-exchange-for-ai-agents/ ; May 2026 release: https://www.okta.com/newsroom/articles/auth0-may-2026-product-innovations/
- Cloudflare MCP Server Portals: https://blog.cloudflare.com/zero-trust-mcp-server-portals/ ; MCP traffic detection: https://blog.cloudflare.com/mcp-security-updates/ ; portal service tokens: https://developers.cloudflare.com/changelog/post/2026-06-26-mcp-portal-service-tokens/ ; agentic commerce (TAP/Agent Pay): https://blog.cloudflare.com/secure-agentic-commerce/
- Visa Trusted Agent Protocol: https://corporate.visa.com/en/sites/visa-perspectives/newsroom/visa-unveils-trusted-agent-protocol-for-ai-commerce.html
- Stripe agentic commerce / Shared Payment Tokens: https://stripe.com/blog/developing-an-open-standard-for-agentic-commerce ; https://docs.stripe.com/agentic-commerce/concepts/shared-payment-tokens
- Mastercard Agent Pay vs Visa comparison (eco.com): https://eco.com/support/en/articles/15192003-mastercard-agent-pay-vs-visa-trusted-agent-2026-compared
- Google AP2 announcement: https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol
- WorkOS on MCP 2026 spec: https://workos.com/blog/mcp-2026-spec-agent-authentication
- FIDO Alliance on AP2 verifiable intent: https://fidoalliance.org/building-the-trust-layer-for-agentic-payments-with-ap2-and-verifiable-intent/
