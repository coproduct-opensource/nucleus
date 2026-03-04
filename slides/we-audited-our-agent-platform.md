---
marp: true
theme: default
paginate: true
backgroundColor: #1a1a2e
color: #e0e0e0
style: |
  section {
    font-family: 'Inter', 'Segoe UI', sans-serif;
  }
  code {
    color: #e06c75;
    background: #2d2d44;
    border-radius: 4px;
    padding: 2px 6px;
  }
  pre {
    background: #16213e;
    border-radius: 8px;
    border: 1px solid #333;
  }
  pre code {
    background: transparent;
    color: #abb2bf;
  }
  h1, h2 {
    color: #61dafb;
  }
  h3 {
    color: #c678dd;
  }
  strong {
    color: #f5a623;
  }
  a {
    color: #61dafb;
  }
  table {
    font-size: 0.85em;
  }
  th {
    background: #16213e;
    color: #61dafb;
  }
  td {
    background: #1a1a2e;
  }
  blockquote {
    border-left: 4px solid #f5a623;
    background: #16213e;
    padding: 0.5em 1em;
    border-radius: 0 8px 8px 0;
  }
  .columns {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1em;
  }
---

<!-- _class: lead -->
<!-- _paginate: false -->

# We Audited Our Own AI Agent Platform

## Here's What We Found.

**5 critical fail-open vulnerabilities** in our own production system

<br>

coproduct-opensource/nucleus

---

# Who We Are

We build **Nucleus** — an open-source security runtime for AI agents.

Policy, enforcement, and audit in one stack.

Last week, we turned our own tools on our **production orchestration platform**.

> Every finding was a variant of the same pattern:
> **security that was present in code but absent in enforcement.**

---

# The Threat Model Has Changed

Your AI agent has three capabilities:

```
Private Data Access  +  Untrusted Content  +  Exfiltration Vector
───────────────────      ─────────────────     ──────────────────
read_files               web_fetch              git_push
read_env                 web_search             create_pr
database access          user input             run_bash (curl)
```

When **all three** are present at autonomous levels:

**Prompt injection = Data exfiltration**

*— Simon Willison, ["The Lethal Trifecta"](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)*

---

# The Standard Defense

A YAML file that says "don't do that."

```yaml
permissions:
  git_push: "ask_human"    # advisory
  web_fetch: "restricted"  # not enforced
  read_files: "allowed"    # who checks?
```

<br>

We wanted to know: **does our own platform do any better?**

---

<!-- _class: lead -->
<!-- _paginate: false -->

# The Five Findings

---

# Finding 1: gRPC With No Authentication

The SPIFFE mTLS path existed — behind a feature flag.

If TLS config failed, the server **silently fell back to plaintext**.

```rust
// Before: silent degradation to insecure
Err(e) => {
    warn!("Failed to build TLS config, starting without mTLS");
    Server::builder() // No auth, no TLS, full access
}
```

Any process on the same network could register fake executors,
enqueue malicious work, or submit fabricated results.

---

# Finding 1: The Fix

**Fail closed.** TLS failure = panic. No fallback.

```rust
// After: fail-closed
Err(e) => panic!(
    "SPIFFE TLS failed: {e}. Refusing insecure gRPC fallback."
),
```

gRPC reflection gated behind `#[cfg(debug_assertions)]`.

---

# Finding 2: Webhooks Accepted Without Verification

`verify_github_signature()` returned **`true`** on empty secret.

Secret defaulted to `""` via `unwrap_or_default()`.

```rust
// Before: empty secret = accept everything
if secret.is_empty() {
    warn!("Webhook signature verification disabled");
    return true; // ← every forged payload passes
}
```

**Impact:** Forge GitHub events to inject work items with malicious directives.
Direct vector for **prompt injection at the orchestration layer**.

---

# Finding 2: The Fix

No secret = **reject all payloads**.

```rust
// After: no secret = no webhooks
if secret.is_empty() {
    error!("Webhook rejected: GITHUB_WEBHOOK_SECRET not configured.");
    return false;
}
```

---

# Finding 3: Sessions That Never Expire

Token endpoint advertised `expires_in: 3600`.

The server **never checked** `created_at` against current time.

- In-memory `HashMap` — no TTL, no cleanup, no size bound
- Compromised tokens valid **forever** (until daemon restart)
- Unbounded growth = trivial **denial of service**

---

# Finding 3: The Fix

24-hour TTL + 10k cap + background reaper.

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

---

# Finding 4: Auth Was Optional

A `maybe_auth!` macro skipped auth when unconfigured.

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

**One missing env var** → approve, reject, drain queue, enable autonomous mode — all public.

---

# Finding 4: The Fix

Unconfigured = **503 on all protected routes**.

```rust
// After: no config = fail closed
} else {
    $routes.layer(axum::middleware::from_fn(
        handlers::auth_not_configured_middleware,
    ))
}
```

The system is **unusable** until properly configured. That's correct.

---

# Finding 5: Hardcoded Secret + No Headers

Cookie secret fallback: `"development-secret-change-in-production-32bytes!"`

Every deployment without explicit config → **same signing key**.

No security headers on any response:
- No HSTS (protocol downgrade)
- No X-Frame-Options (clickjacking)
- No X-Content-Type-Options (MIME sniffing)
- No CSP

**Fix:** Secret required (≥ 32 bytes) + `security_headers` middleware on all responses.

---

<!-- _class: lead -->
<!-- _paginate: false -->

# The Pattern

---

# Fail-Open Defaults

Every finding has the same root cause.

| Finding | Secure Code Existed? | Default Behavior |
|---------|---------------------|------------------|
| gRPC auth | Yes (SPIFFE mTLS) | Falls back to plaintext |
| Webhooks | Yes (HMAC-SHA256) | Disabled on empty secret |
| Session expiry | Yes (advertised TTL) | Never enforced |
| Route auth | Yes (OAuth/API key) | Skipped when unconfigured |
| Cookie secret | Yes (env var) | Hardcoded fallback |

Security features **pass code review** because they exist.
They **pass testing** because tests configure them.
They **fail in production** because deployments don't.

---

# Why It's Worse for Agent Platforms

Web app session bug → attacker accesses **user data**.

Agent platform session bug → attacker can:

- **Enqueue work** that instructs agents to exfiltrate secrets
- **Approve operations** that should require human review
- **Inject webhooks** that look like legitimate GitHub events
- **Register rogue executors** that intercept credentials

Every orchestration vulnerability is an **exfiltration vulnerability**.

The agents have the access. The guardrails must be real.

---

# How We Catch This Now

```bash
cargo install nucleus-audit

nucleus-audit scan --pod-spec your-agent.yaml

# ╔══════════════════════════════════════════════════════════════╗
# ║  Nucleus PodSpec Security Scan                              ║
# ╠══════════════════════════════════════════════════════════════╣
# ║  Pod: yolo-agent                                            ║
# ║  Findings: 4 critical, 2 high, 1 medium                    ║
# ╠══════════════════════════════════════════════════════════════╣
# ║  [CRITICAL] Lethal trifecta detected                        ║
# ║  [CRITICAL] 7 credentials exposed                           ║
# ║  [HIGH]     No network restrictions                         ║
# ║  [HIGH]     No VM isolation                                 ║
# ╚══════════════════════════════════════════════════════════════╝
# Exit code: 1
```

Drop it in CI. Block unsafe deployments.

---

# Static Analysis + Runtime Enforcement

**`nucleus-audit scan`** catches misconfigurations before deploy.

**Nucleus runtime** enforces at execution:
- Firecracker microVMs — isolated by default
- Enforcing tool proxy — every side effect is checked
- Permissions only **tighten**, never relax
- Hash-chained audit logs — tampering is detectable

Policy without enforcement is theater.

---

<!-- _class: lead -->
<!-- _paginate: false -->

# The Takeaway

---

# Advisory Security Doesn't Work

We build security tools for AI agents.

We still had **five critical fail-open vulnerabilities**.

<br>

**Every default must be secure.**
**Every missing config must be a hard failure.**
**Every policy must be enforced, not just declared.**

<br>

> Warn-and-continue is indistinguishable from no security
> in the deployment where someone forgot an env var.

---

<!-- _class: lead -->
<!-- _paginate: false -->

# Try It

```bash
cargo install nucleus-audit
nucleus-audit scan --pod-spec your-agent.yaml
```

**github.com/coproduct-opensource/nucleus**

MIT / Apache-2.0
