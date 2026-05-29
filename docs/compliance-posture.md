# nucleus Compliance Posture

**Status:** Honest map from shipped controls to framework requirements.
**Last updated:** 2026-05-29.
**Scope:** the public `verifier.coproduct.io` deployment + the
in-process SDKs + the OSS code customers run themselves.
**Audience:** customer compliance officers, internal vendor reviews,
external auditors.

This is not a legal opinion. It's a faithful map from what we ship
to what each framework asks for, so your compliance team can move
faster on internal review. Where we have a gap, we name it. Where
remediation is in flight, we link to the tracking task.

## TL;DR by framework

| Framework | Effective | Penalty | Our posture | Notes |
|---|---|---|---|---|
| **EU AI Act Article 50** | 2026-08-02 | €15M or 3% global turnover | **Satisfies** machine-readable marking via bundle + C2PA export | See [eu-ai-act-article-50.md](./eu-ai-act-article-50.md) |
| **NIS2 (EU 2022/2555)** | 2024-10 (transposition deadline 2024); Member-State enforcement underway through 2026 | up to €10M or 2% global turnover | **Largely satisfies** Article 21 risk-management controls; **opt-in** for Article 23 incident reporting | We are an essential supplier to subject entities; mapped below |
| **SOC 2 Type II** | Customer-driven (80% of Series B+ require) | Sales gate, not regulatory | **Substantially aligned**; formal Type II audit committed for FY26 | Trust Services Criteria mapping below |
| **GDPR (EU 2016/679)** | 2018-05 | up to €20M or 4% global turnover | **Satisfies** Article 32 (security of processing) + lawful-basis story for the public log | DPO: `security@coproduct.io` |
| **NIST AI RMF 1.0** | Voluntary | n/a | Mapped at the agent-runtime layer; verifier service is GOVERN-aligned | |
| **ISO 42001 (AI MS)** | Optional | n/a | Aligned conceptually; formal certification post-MVP | |

---

## EU AI Act Article 50 — machine-readable marking

The full mapping is in [eu-ai-act-article-50.md](./eu-ai-act-article-50.md);
the table below is the executive summary.

| Article 50 §2 obligation | nucleus surface |
|---|---|
| "marked in a machine-readable format" | `Bundle` JSON or C2PA manifest export |
| "detectable as artificially generated" | `EdgeKind::PodAdmit` + `EdgeKind::LlmCall` entries identify the agent runtime |
| effective + interoperable + robust + reliable (§6) | Hand-rolled JWS (no alg=none CVE class); Ed25519 / SHA-256 in pure Rust; C2PA + in-toto + SLSA + Sigstore exports; quarterly skeptical-code audits |

**Penalty exposure.** Article 99 §3 caps Article 50 violations at
€15M or 3% global annual turnover. A bundle satisfies the
machine-readable-marking requirement at the **upstream provenance
layer**; downstream pixel-domain watermarking is the caller's
responsibility (and a complementary market — see the threat-model
doc's T5 for downgrade detection).

---

## NIS2 — Article 21 (cybersecurity risk management)

NIS2 imposes risk-management obligations on "essential" and
"important" entities; suppliers to those entities inherit
diligence requirements. Article 21 lists ten control families
(21(2)(a) through 21(2)(j)).

| 21(2) clause | Subject | Our posture |
|---|---|---|
| (a) Risk analysis + information system security policies | risk register | This document + [verifier-service-threat-model.md](./verifier-service-threat-model.md). Quarterly review. |
| (b) Incident handling | runbook | Disclosure email + 90-day window — see threat model. Incident-runbook PRD in flight. |
| (c) Business continuity, backup, crisis management | DR | Fly.io volume + S3 daily snapshot. Two-region read replication tracked in #81 (Flycast mesh). |
| (d) Supply chain security | vendor mgmt | All dependencies vendored via cargo lock + npm lock; quarterly `cargo audit` + `npm audit` in CI |
| (e) Security in acquisition, development, maintenance | SDLC | `clippy -D warnings` on every PR; skeptical-code-auditor pass on every major release; commit signing via Sigstore (in flight, task #97) |
| (f) Effectiveness assessment | test discipline | 65+ envelope tests; 47+ verifier-service tests; 40+ control-plane-server tests; integration tests cover every code path. Tests run on every PR. |
| (g) Cyber hygiene + training | training | Internal documentation + onboarding playbook (not public). Vendor team's `clippy` discipline + audit pattern is the de-facto control. |
| (h) Cryptography + encryption | crypto | Ed25519 + SHA-256 + COSE_Sign1 (C2PA); TLS 1.3 at the Fly edge; secrets via Fly secrets (env-injected); STH signing key zeroized on Debug. RSA explicitly not supported for new bundles. |
| (i) Human resources security | personnel | Internal — not public. |
| (j) MFA + zero trust | access | All operator access to Fly via `fly auth` + WebAuthn; SPIFFE JWT-SVID auth on control-plane (#79). |

**Article 23 — incident reporting.** NIS2 requires 24-hour
early-warning + 72-hour incident notification for significant
incidents. nucleus's commitment for our hosted service: 24h
notification to all impacted customers + a public post-mortem
within 14 days. This is policy, not a technical control;
documented in our DPA (Data Processing Addendum) issued to
customers.

---

## SOC 2 — Trust Services Criteria

Common Criteria + Security TSC mapping. We are pre-audit but
substantially aligned; formal Type II audit is committed for
FY26 Q4.

### CC6.1 — Logical and physical access controls

| Requirement | Posture |
|---|---|
| Least privilege | SPIFFE-mTLS on control plane (#79); SQL-level RBAC on the verifier DB N/A in v1 (single writer) |
| Authentication | JWT-SVID via OIDC OP; Fly operator access via WebAuthn |
| Authorization | Subject-prefix federation rules in nucleus-oidc-provider; allowed-audience + allowed-subject-prefix gates in control-plane (#96) |

### CC6.6, CC7.1 — Monitoring + detection

| Requirement | Posture |
|---|---|
| Anomaly detection | Structured `tracing` logs to stderr; Fly log shipper; per-IP rate-limit triggers (#70) |
| Vulnerability mgmt | `cargo audit` + Dependabot |
| Incident response | Disclosure policy in threat model |

### CC7.2 — Change management

| Requirement | Posture |
|---|---|
| Code review | PR review mandatory; CI gates: build + clippy + tests + skeptical-code-auditor |
| Release process | Versioned crates + semver; Fly deploys via `fly deploy` from CI on main-branch merge |

### CC8.1 — System operations

| Requirement | Posture |
|---|---|
| Backup | Fly volume snapshots daily; SQLite WAL mode → durable on crash |
| Capacity | `MAX_INFLIGHT_JOBS` + `MAX_CONCURRENT_REQUESTS` + `tower-governor` per-IP — see threat model T6 |

### Availability TSC

| Requirement | Posture |
|---|---|
| Uptime SLO | 99.9% targeted on verifier.coproduct.io; Fly auto-stop=off, min_machines_running=1 |
| Incident response | 24h notification per NIS2; status page commitment |

### Processing Integrity TSC

| Requirement | Posture |
|---|---|
| Input validation | RFC 8725 alg allowlist (EdDSA only) on every JWS; canonical JSON (`serde_json` deterministic) for hashing; hex/base64 decoders fail loud |
| Audit logs | Append-only `log_entries` table with chain hash (#69); future RFC 9162 Merkle (#95) |
| Correctness | Same Rust verifier across hosted service + JS SDK + Python SDK — byte-for-byte identical math |

### Confidentiality TSC

| Requirement | Posture |
|---|---|
| Data at rest | SQLite on encrypted Fly volume; signing key never written to disk in plaintext |
| Data in transit | TLS 1.3 at edge; internal Fly 6PN encrypted at the WireGuard layer |
| Data minimization | Verifier service archives bundle SHA + report only by default; raw bundle bytes opt-in (#72 retention sweeper) |

### Privacy TSC

Customer payloads pass through the verify endpoint; we do NOT
archive them by default. The `payload_size_bytes` we store is a
length only (no content). When opt-in archival lands (#72), the
retention sweeper enforces deletion after 90 days.

---

## GDPR

**Lawful basis for processing.**

- **Verifier service `POST /v1/verify`**: the caller submits a
  bundle for verification — legitimate-interest basis (Article 6(1)(f))
  for the controller (us), processing strictly limited to running
  the verification function. We do NOT retain the bundle body by
  default.
- **Public transparency log (`log_entries`)**: the envelope hash +
  timestamp are necessary for the integrity guarantee of the
  service we provide; published under legitimate interest. No
  personal data in the log entries themselves (hashes are not
  personal data per CJEU C-582/14 *Breyer*).
- **Marketing site analytics**: anonymized via Plausible (no
  cookies, no IP storage). Consent banner deliberately not
  required.

**Article 32 (security of processing).** Covered by the SOC 2
Confidentiality TSC mapping above + threat model defenses.

**Article 33 (breach notification).** 72-hour notification window
to supervisory authority + 24h notification to affected
controllers under NIS2. Combined runbook lives in our DPA.

**Data subject rights.** The verifier service holds no personal
data by default. If a buyer archives bundles containing personal
data (their decision, their lawful basis), they remain the
controller and the deletion mechanism is `DELETE FROM
verifications WHERE envelope_hash = ?` via our admin API
(post-#72 retention sweeper).

**Data Protection Officer.** `security@coproduct.io` doubles as
the DPO contact pending formal appointment. Full DPO terms in our
DPA.

**International transfers.** Fly.io's iad region (Virginia, US).
Standard Contractual Clauses available on request for EU
customers; multi-region read replication tracked in #81.

---

## NIST AI RMF 1.0

The NIST AI Risk Management Framework defines four functions:
GOVERN, MAP, MEASURE, MANAGE. The verifier service contributes to
**GOVERN** (transparency + accountability):

- GOVERN 1.3 (organizational risk tolerance): published threat
  model
- GOVERN 1.4 (legal + regulatory mapping): this document
- GOVERN 1.5 (transparency to stakeholders): public verifier +
  open-source code
- GOVERN 1.7 (incident response): disclosure policy + 90-day
  window

The MAP / MEASURE / MANAGE functions apply at the AI agent layer
itself, which lives outside the verifier service. Customers
operating agents through the control plane inherit MAP/MEASURE
posture from the lineage records we produce.

---

## ISO 42001 (AI Management System)

ISO 42001 (2023) is a management-system standard for AI. nucleus
is conceptually aligned: we maintain an AI risk register (this
document), publish a threat model, follow a defined SDLC, and run
quarterly audits.

Formal certification is post-MVP. The certification path is
budgeted for FY27.

---

## What this doc is NOT

- **Legal advice.** Determining whether each framework applies to
  your specific use case is a question for your counsel.
- **A SOC 2 report.** Once the Type II audit closes (target FY26
  Q4), we'll publish the auditor's report under NDA.
- **A penetration test.** External pen-test commissioning is
  budgeted; first report no later than 60 days before EU AI Act
  Article 50 effective date.

## Updates + verification

This document is reviewed quarterly alongside the threat model.
The current revision is signed by the maintainer in the repo
commit history (`git log docs/compliance-posture.md`). When you
hand this to your auditor, point them at the commit hash so they
can verify they're reading the canonical version.

Issues, gaps, or corrections: open a PR or email
`security@coproduct.io`.
