# nucleus Public Audit Charter

**Status:** Public, binding commitment.
**Effective:** 2026-05-29.
**Renewal:** annually, on the anniversary of the prior revision.

This document is the long-form trust posture nucleus commits to.
It's the document you forward to your CISO when they ask "how do
we know to trust this?" It names cadences, auditors, scope, and
publication rules.

Two principles drive the cadences below:

1. **No one trusts a system because the vendor says it's secure.**
   The only thing that counts is what an adversary tried to break
   and couldn't.
2. **Verifiability beats reputation.** Every audit report we
   commission is published (under NDA where commercial terms
   require, in summary form when not), so a buyer can read the
   findings instead of taking our word for the result.

## Continuous controls

These run on every PR, before any merge to `main`. The PR will
not merge red.

| Control | Tool | Scope |
|---|---|---|
| Build | `cargo build` | all crates, `--all-features` |
| Format | `cargo fmt --check` | all crates |
| Lint | `cargo clippy -- -D warnings` | all crates, all targets |
| Test | `cargo test` | all crates |
| Vendor neutrality | `scripts/check-vendor-neutrality.sh` | nucleus public-tree crates |
| Algorithm pinning | grep + match against `algorithm-pin.yaml` | every JWS-handling site |
| Adversarial bundle corpus | `cargo test -p nucleus-envelope-adversarial-corpus` (#89) | the envelope verifier |
| Dependency audit | `cargo audit` | all crates; fail on RUSTSEC advisories |
| SBOM | `cargo sbom` → `sbom.json` artifact | every release tag |

Failures block merge unconditionally. Operator override is
possible but logged + reviewed at the next quarterly audit.

## Quarterly skeptical-code audit

Cadence: **every 13 weeks**, starting 2026-Q3.

Scope: every nucleus crate touched since the prior audit
(`git diff` from the last audit's pinned hash). The auditor is
the in-tree `skeptical-code-auditor` agent OR a designated
in-tree reviewer; verdicts are deliberately adversarial in
posture.

Output: a `docs/audits/<YYYY>-<QQ>-skeptical.md` document in the
public repo with:

- CRIT / HIGH / MED / LOW findings, each with:
  - title, location (file:line), reproducer, mitigation, residual
- closed-from-last-time count
- coverage gaps the auditor identified
- the next-audit hash to diff against

Past audits to reference: the v1 nucleus-oidc-provider audit
already published at [`oidc-provider-audit-v1.md`](./oidc-provider-audit-v1.md)
(zero CRIT, five HIGH closed, seven MED closed, five LOW closed)
is the template.

## Biennial external cryptographic-protocol audit

Cadence: every 24 months. First engagement: **scheduled for
2026-Q3** (target: pre-Article-50 effective date).

Scope: the cryptographic and information-flow surfaces of
nucleus — JWS signing, Merkle-tree construction, COSE/C2PA
emission, capability lattice, taint algebra. Behavioural
correctness (verify-bundle returns the right answer on
adversarial inputs) is in scope; UI / marketing-site / billing
flows are out of scope.

Auditor pool (any one of these qualifies; we'll publish the
selected vendor in the engagement announcement):

| Auditor | Strength | Typical engagement |
|---|---|---|
| [Trail of Bits](https://trailofbits.com) | Cryptography, Rust, attested computation | 4-6 weeks, public summary report |
| [NCC Group](https://nccgroup.com) | Standards conformance (RFC 9162, RFC 8037), formal methods | 3-5 weeks, full + summary reports |
| [Cure53](https://cure53.de) | Web-stack + crypto, public reports | 2-4 weeks, public-by-default |
| [Doyensec](https://doyensec.com) | Application security, supply chain | 3-4 weeks, NDA + summary |
| [Sec3](https://sec3.dev) | Formal verification at the Rust / WASM boundary | 4-6 weeks, public |

Publication: the **full report** is provided to any buyer under
NDA; the **summary report** (findings count, severity
breakdown, fix status) is published in `docs/audits/`.

If a finding is not yet remediated at publication time, the
publication is delayed by up to 30 days to allow the fix to
land. After 30 days, the finding is disclosed regardless,
following coordinated-disclosure norms.

## Bug bounty (planned, FY27)

A formal bug bounty program is **planned for FY27 Q2** once the
v1 hosted service is past 90 days uptime + first external audit
closes. Pre-program disclosures should go to
`security@coproduct.io`.

Indicative tiers (subject to revision when the program launches):

| Severity | Bounty range (USD) |
|---|---|
| Critical (signature forgery, key extraction) | $5,000 – $25,000 |
| High (auth bypass, log tampering) | $1,000 – $5,000 |
| Medium (DoS, info disclosure) | $250 – $1,000 |
| Low (config issues) | $0 – $250 |

We will use a third-party platform (HackerOne or Intigriti) to
triage.

## Disclosure policy

Vulnerability disclosure: `security@coproduct.io`.

- We **acknowledge** receipt within 1 business day.
- We commit to a **triage decision** within 5 business days.
- The **coordinated disclosure window** is 90 days from
  acknowledgement, or **14 days** for actively-exploited issues.
- We commit to **acknowledging the reporter** in the public
  advisory unless they ask otherwise.
- We do **not** pursue legal action against good-faith security
  researchers acting under the disclosure window, per the
  [Disclose.io](https://disclose.io) safe-harbour template.

## Audit independence

The biennial external audit MUST be conducted by an organisation
nucleus does NOT engage as a development consultancy, advisor, or
investor (excluding ordinary security-services billing for the
audit engagement itself). We commit to disclosing any prior
commercial relationship in the engagement announcement.

If two consecutive biennial audits are conducted by the same
firm, the firm rotates for the third — limiting auditor capture
risk per ISACA's "audit rotation" guidance.

## Audit-trail integrity for THIS document

The doc you're reading is signed in the repo's commit history
(`git log docs/audit-charter.md`). The current revision's
canonical hash is whatever `git rev-parse HEAD` says for the
latest commit touching this file. When you cite this charter to
an auditor, cite the commit hash too — that's the version we are
bound by.

Revisions REDUCING our commitments (e.g. lengthening cadences,
narrowing scope) MUST be approved by a security-team review
and announced 30 days before taking effect. Revisions
STRENGTHENING our commitments (shorter cadences, broader scope)
take effect immediately.

## Public commitments at a glance

We commit to:

- Every PR passes the continuous controls listed above
- Quarterly skeptical-code audit with public verdict
- Biennial external cryptographic audit with public summary
- Safe-harbour-protected vulnerability disclosure (90/14 day windows)
- Auditor rotation every two cycles
- Disclosure of prior commercial ties with selected auditor
- Publication of the audited commit hash with every audit

We do NOT commit to:

- A specific date for FedRAMP / FedRAMP-equivalent certification
  (premature for an MVP-stage company; will revisit when revenue
  warrants)
- Formal Common Criteria certification (out of scope for a
  cryptographic library at this maturity stage; revisit FY28)
- Pen-testing every Fly.io deploy region (single-region in v1;
  multi-region with sovereign cloud is task #81)

## Contact

- Security disclosures: `security@coproduct.io`
- Compliance + audit liaison: same address
- Public archive of past audits: `docs/audits/` in the repo
