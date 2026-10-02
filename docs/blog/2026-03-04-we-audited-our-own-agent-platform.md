# We Audited Our Own AI Agent Platform. Here's What We Found.

*March 4, 2026*

We build [Nucleus](https://github.com/coproduct-opensource/nucleus), an open-source security runtime for AI agents. Last week, we turned our own tools on our production orchestration platform — the closed-source system that actually runs our agents — and found **5 critical fail-open vulnerabilities**.

Every one of them was a variant of the same pattern: **security that was present in code but absent in enforcement**.

This is the story of what we found, why it matters for anyone running AI agents in production, and what we did about it.

## The Threat Model Has Changed

If you're running AI agents that can read files, process web content, and push code, you have what Simon Willison calls the [uninhabitable state](https://simonwillison.net/2025/Jun/16/the-uninhabitable-state/):

```
Private Data Access  +  Untrusted Content  +  Exfiltration Vector
```

When all three are present, prompt injection becomes data exfiltration. A carefully crafted comment in a PR, a poisoned web page, a manipulated search result — any of these can instruct your agent to send your secrets somewhere they shouldn't go.

The standard defense is a YAML configuration file that says "don't do that." We wanted to know: does our own platform do any better?

## What We Found

We ran a systematic security audit of our orchestration daemon — the service that manages work queues, dispatches tasks to agents, handles GitHub webhooks, and serves the operations dashboard. Here are the five critical findings.

### Finding 1: gRPC Server With No Authentication

**The vulnerability:** Our gRPC server (port 4003) had no authentication middleware by default. The SPIFFE mTLS path existed behind a feature flag, but if TLS configuration failed at startup, the server silently fell back to plaintext with a warning log.

```rust
// Before: silent degradation to insecure
Err(e) => {
    warn!("Failed to build TLS config, starting without mTLS");
    Server::builder() // No auth, no TLS, full access
}
```

**Why it matters:** Any process on the same private network could register fake executors, enqueue malicious work items, or submit fabricated results. gRPC reflection was always enabled, making service discovery trivial.

**The fix:** TLS failure now panics. If SPIFFE mTLS can't be established, the gRPC server refuses to start. Reflection is gated behind `#[cfg(debug_assertions)]`.

```rust
// After: fail-closed
Err(e) => panic!("SPIFFE TLS failed: {e}. Refusing insecure gRPC fallback."),
```

### Finding 2: Webhook Signature Verification Disabled by Default

**The vulnerability:** The `verify_github_signature()` function returned `true` when the webhook secret was empty. Since the secret defaulted to an empty string via `unwrap_or_default()`, a fresh deployment accepted **any** webhook payload without verification.

```rust
// Before: empty secret = accept everything
if secret.is_empty() {
    warn!("Webhook signature verification disabled");
    return true; // ← every forged payload passes
}
```

**Why it matters:** An attacker could forge GitHub webhook events to enqueue work items with crafted payloads, trigger workflows with malicious directives, or inject PR review comments that steer agent behavior. This is a direct vector for prompt injection at the orchestration layer.

**The fix:** Empty secret now rejects all payloads.

```rust
// After: no secret = no webhooks
if secret.is_empty() {
    error!("Webhook rejected: GITHUB_WEBHOOK_SECRET is not configured.");
    return false;
}
```

### Finding 3: Sessions That Never Expire

**The vulnerability:** The session store was an in-memory `HashMap` with no TTL enforcement, no cleanup task, and no size bound. The token endpoint advertised `expires_in: 3600` in its response — but the server never checked `created_at` against the current time.

**Why it matters:** Two problems. First, a compromised token could never be revoked without restarting the daemon. Second, the unbounded HashMap meant an attacker could hit the token endpoint repeatedly to exhaust memory — a trivial denial of service.

**The fix:** Sessions now have a 24-hour TTL enforced at read time, a 10,000 session size cap, and a background reaper that prunes expired sessions every 5 minutes.

```rust
pub fn spawn_session_reaper(sessions: SessionStore) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            let now = Utc::now().timestamp();
            let mut store = sessions.write().await;
            store.retain(|_, s| now - s.created_at <= SESSION_TTL_SECS);
        }
    })
}
```

### Finding 4: Authentication That Was Optional

**The vulnerability:** A `maybe_auth!` macro made authentication entirely conditional. If no auth mechanism was configured — no OAuth, no API keys, no client credentials — every API route was served without any authentication at all.

```rust
// Before: no config = no auth = full access
macro_rules! maybe_auth {
    ($routes:expr) => {
        if auth_enabled {
            $routes.layer(auth_middleware)
        } else {
            $routes // ← every route wide open
        }
    };
}
```

**Why it matters:** A single missing environment variable silently degraded every protected endpoint to zero security. State-mutating operations — approve, reject, pause, resume, drain queue, enable autonomous mode — all became publicly accessible.

**The fix:** When auth is not configured, all protected routes now return 503 Service Unavailable. The system is unusable until properly configured, which is exactly right.

```rust
// After: no config = fail closed
} else {
    $routes.layer(axum::middleware::from_fn(
        handlers::auth_not_configured_middleware,
    ))
}
```

### Finding 5: Hardcoded Cookie Secret + No Security Headers

**The vulnerability:** If `DASHBOARD_COOKIE_SECRET` wasn't set, the fallback was a hardcoded string: `"development-secret-change-in-production-32bytes!"`. Additionally, no security headers (HSTS, X-Frame-Options, CSP, X-Content-Type-Options) were set on any response.

**Why it matters:** The hardcoded secret meant every deployment without explicit configuration shared the same signing key. The missing headers left the dashboard vulnerable to clickjacking, protocol downgrade, and MIME sniffing attacks.

**The fix:** Cookie secret is now required when any auth mechanism is configured, validated to be at least 32 bytes. A `security_headers` middleware adds HSTS, X-Frame-Options DENY, X-Content-Type-Options nosniff, and Referrer-Policy to every response.

## The Common Pattern: Fail-Open Defaults

Every finding shares the same root cause: **the secure path existed but wasn't the default path**.

| Finding | Secure Code Existed? | Default Behavior |
|---------|---------------------|------------------|
| gRPC auth | Yes (SPIFFE mTLS) | Falls back to plaintext |
| Webhook verification | Yes (HMAC-SHA256) | Disabled on empty secret |
| Session expiry | Yes (advertised TTL) | Never enforced |
| Route auth | Yes (OAuth/API key) | Skipped when unconfigured |
| Cookie secret | Yes (env var) | Hardcoded fallback |

This is the most dangerous category of vulnerability. The security features pass code review because they exist. They pass testing because tests configure them. They fail in production because the deployment doesn't set the right environment variables, and the code silently degrades instead of refusing to start.

**The fix is always the same: fail closed.** If the secure configuration isn't present, the system should refuse to operate — not operate insecurely.

## What This Means for AI Agent Security

These aren't exotic vulnerabilities. They're standard web application security issues that happen to exist in a platform that orchestrates AI agents. But the blast radius is different.

When your web app has a session expiry bug, an attacker can access user data. When your agent orchestration platform has a session expiry bug, an attacker can:

- Enqueue work items that instruct agents to read and exfiltrate secrets
- Approve autonomous operations that should require human review
- Inject webhook payloads that look like legitimate GitHub events
- Register rogue executors that intercept credentials and prompts

The uninhabitable state means that every orchestration vulnerability is also an exfiltration vulnerability. The agents have the access. The question is whether the guardrails are real.

## How We Catch This Now

We built `nucleus-audit scan` to catch these patterns statically — before deployment:

```bash
cargo install nucleus-audit

nucleus-audit scan --pod-spec your-agent.yaml
```

The scan checks for:
- ** Uninhabitable state risk** — does this configuration combine private data, untrusted content, and exfiltration?
- **Permission surface area** — how many capabilities are granted at autonomous levels?
- **Network posture** — is egress restricted or wide open?
- **Isolation level** — is the agent running in a VM, a container, or on bare metal?
- **Credential exposure** — how many secrets are passed to the agent?
- **Timeout hygiene** — are there execution time limits?

Exit code is non-zero when critical or high findings exist. Drop it into CI and block unsafe deployments.

```bash
# CI integration
nucleus-audit scan --pod-spec agent.yaml --format json
echo $?  # 0 = clean, 1 = critical/high findings
```

Static analysis catches misconfigurations. But as our own audit proved, you also need runtime enforcement that can't be degraded. That's why Nucleus runs agents inside Firecracker microVMs with an enforcing tool proxy — the permissions are checked on every operation, and they can only tighten, never relax.

## The Takeaway

We build security tools for AI agents. We still had five critical fail-open vulnerabilities in our own platform.

The lesson isn't that security is hard (it is). The lesson is that **advisory security doesn't work**. Warn-and-continue is indistinguishable from no security at all in the deployment that matters — the one where someone forgot to set an environment variable.

Every default must be secure. Every missing configuration must be a hard failure. Every policy must be enforced, not just declared.

That's what Nucleus does. And we know it works, because we used it to find the holes in our own platform.

---

*Nucleus is open source under MIT/Apache-2.0. [Star it on GitHub](https://github.com/coproduct-opensource/nucleus), try `nucleus-audit scan` on your agent configs, and [file issues](https://github.com/coproduct-opensource/nucleus/issues) when you find gaps.*
