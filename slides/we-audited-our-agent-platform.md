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

# Why This Isn't Turtles All The Way Down

---

# The Honest Problem

We have 6 Kani SMT proofs, 233 proptest algebraic laws, and an OWASP gauntlet.

**None of them would have caught these 5 bugs.**

The proofs verify the **lattice algebra** — if enforcement happens,
permissions compose correctly and can only tighten.

Every bug was in the **integration layer** — the code that decides
**whether to enforce at all**.

---

# Two Different Failure Modes

```
┌──────────────────────────────────────────────────────────────┐
│  "Is the lock correct?"          vs.   "Is the lock on?"    │
│                                                              │
│  Kani proves: ν(ν(x)) = ν(x)          maybe_auth! says:    │
│  Proptest: a ∧ (b ∨ c) =              if auth_enabled {    │
│    (a ∧ b) ∨ (a ∧ c)                    enforce()          │
│  Gauntlet: CVE coverage                } else {             │
│                                          pass_through()  ←  │
│  ✅ Formally verified                  }                    │
│                                        ❌ Not verified      │
└──────────────────────────────────────────────────────────────┘
```

Our formal methods proved the lock works. They didn't check if anyone locked it.

---

# Kani Bounded Model Checking

Six formal proofs run nightly via `cargo kani`:

```rust
#[kani::proof]
fn proof_normalize_idempotent() {
    let x = build_symbolic_permissions();
    let once = normalize(x);
    let twice = normalize(once);
    assert!(perm_lattice_eq(once, twice)); // ν(ν(x)) = ν(x)
}
```

| Property | What It Proves |
|----------|---------------|
| `normalize_idempotent` | ν(ν(x)) = ν(x) — normalizing twice changes nothing |
| `normalize_deflationary` | ν(x) ≤ x — enforcement only tightens |
| `normalize_monotone` | x ≤ y ⟹ ν(x) ≤ ν(y) — order is preserved |
| `capability_distributive` | a ∧ (b ∨ c) = (a ∧ b) ∨ (a ∧ c) |
| `permission_distributive` | Full lattice distributivity |
| `frame_finite_distributivity` | Frame axiom: meets distribute over joins |

---

# Property-Based Testing: 233+ Algebraic Laws

Not example-based. **Proptest generates random inputs and checks invariants.**

```rust
proptest! {
    #[test]
    fn graded_associativity(
        m in arb_permission_lattice(),
        f in arb_operation(),
        g in arb_operation()
    ) {
        // (m >>= f) >>= g  ≡  m >>= (λx. f(x) >>= g)
        let left = m.and_then(&f).and_then(&g);
        let right = m.and_then(&|x| f(x).and_then(&g));
        assert!(perm_lattice_eq(left, right));
    }
}
```

Verified: **lattice laws, Heyting adjunction, graded monad laws,
frame distributivity, nucleus operator properties, isolation lattice.**

---

# OWASP LLM Security Gauntlet

70 tests mapping **real CVEs from 2025-2026** to portcullis defenses:

| Attack (Real CVE) | Vector | Nucleus Defense | Verdict |
|---|---|---|---|
| RoguePilot (Orca 2025) | Symlink credential theft | cap-std path resolution | Defended |
| Rules File Backdoor | Unicode injection | Network isolation + trifecta | Partial |
| Config File Exec (CVE-2025-59536) | Config as code | Sandbox proof requirement | Strong |
| DNS Exfiltration (CVE-2025-55284) | Ping → DNS leak | **5 independent layers** | Strong |
| MCP Tool Poisoning (Invariant Labs) | Dynamic tool injection | Compile-time tool defs | Immune |

Plus 3 libfuzzer targets in CI: command injection, path traversal, serde bypass.

---

# The Verification Stack

```
┌─────────────────────────────────────────────────┐
│  Kani SMT Proofs         6 proofs (nightly CI)  │  ← proves laws hold
│  ──────────────────────────────────────────────  │     for ALL inputs
│  Proptest Laws           233+ properties        │  ← statistical
│  ──────────────────────────────────────────────  │     confidence
│  OWASP Gauntlet          70 attack scenarios    │  ← real CVE
│  ──────────────────────────────────────────────  │     coverage
│  Fuzzing                 3 libfuzzer targets    │  ← crash
│  ──────────────────────────────────────────────  │     resistance
│  776 Tests               CI-gated on every PR   │  ← correctness
└─────────────────────────────────────────────────┘
```

Every layer is auditable. `cargo kani -p portcullis` to verify yourself.

---

# The Gap: Integration Verification

What's proven today vs. what isn't:

| Layer | Verified? | Method |
|-------|-----------|--------|
| Lattice algebra (meet, join, distributivity) | **Yes** | Kani SMT, proptest |
| Nucleus operator (idempotent, deflationary, monotone) | **Yes** | Kani SMT |
| Trifecta constraint (obligations added correctly) | **Yes** | Proptest, OWASP gauntlet |
| Attack resilience (real CVEs blocked) | **Yes** | OWASP gauntlet, fuzz |
| Daemon activates enforcement on all paths | **No** | Found by audit |
| Config defaults are fail-closed | **No** | Found by audit |
| gRPC server refuses insecure fallback | **No** | Found by audit |

The bottom three rows are where the 5 bugs lived.

---

# The Lesson

Formal methods on the **engine** don't help if the **ignition** is optional.

You need both:

1. **Correct enforcement** — the lattice proofs guarantee this
2. **Mandatory enforcement** — fail-closed defaults guarantee this

We had (1) without (2). That's what the 5 fixes addressed.

**Next:** extend Kani proofs to the integration boundary —
prove that every code path through the daemon either
enforces the lattice or panics. No silent degradation.

---

<!-- _class: lead -->
<!-- _paginate: false -->

# The Takeaway

---

# What We Actually Learned

We build security tools for AI agents.

We had a **formally verified permission engine** sitting behind
**five fail-open integration bugs**.

<br>

The lattice algebra was correct. The deployment activation was not.

<br>

**Formal methods are necessary but not sufficient.**
**Fail-closed defaults are the other half.**
**Neither works without the other.**

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
