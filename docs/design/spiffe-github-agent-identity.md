# Design Spike — SPIFFE → GitHub agent identity

**Status:** design spike (strategy deliverable). No runtime change. Docs-only.
**Author of record:** decision-proxy spike, 2026-08-10.
**Scope:** let a nucleus SPIFFE agent push to / act on GitHub under its *own* attested
identity, with the push mediated by the IFC egress boundary this repo just proved.
**This is not part of the declassification program** — it is a separate design.

---

## 0. TL;DR

GitHub will not authenticate a `git push` from an external OIDC/SPIFFE token. So the
bridge is a **GitHub App** whose private key stays in the **host TCB** (exactly where the
broker secret and cloud audit-credentials already live — never in the sandbox). The agent
presents its **SVID** to the host; the host verifies it and mints a **short-lived,
repo-scoped GitHub App installation token**, delivered over the existing served-once
workload-API provisioning pattern (`FETCH_*`). Each push is authorized by the agent's own
SPIFFE identity — no shared PAT.

The differentiator: a `git push` egresses code and data, so it is a **mediated egress
sink** governed by the same IFC / declassification boundary as `web_fetch` and
`credentialed_egress`. A compromised agent structurally cannot exfiltrate a secret via a
`git push`. **No other agent runtime can say this.**

Attribution is layered on top with **gitsign/Sigstore keyless signing**, where the Fulcio
certificate's SAN is the agent's **SPIFFE ID** (Fulcio has a native SPIFFE issuer type).
Honest caveat: GitHub will *not* render the native "Verified" badge for these commits;
verifiability is out-of-band (`gitsign verify` + Rekor), which is arguably stronger but is
a real UX tradeoff and must be stated plainly.

---

## 1. The nucleus components this reuses (grepped, with paths)

Everything below already exists in-tree. This spike is a **wiring/composition** design, not
new subsystems.

### 1.1 The OIDC ↔ SPIFFE bridge — and its *direction* (the load-bearing correction)

- `crates/nucleus-node/src/oidc.rs` — `POST /v1/oidc/github`. This exchanges a **GitHub
  Actions OIDC token + client-generated CSR** for a **nucleus X.509 SVID**
  (`spiffe://<trust-domain>/ns/github/sa/{org}/{repo}`), with JWKS validation, `jti` replay
  protection, repo/org allowlist, no key escrow (private key stays client-side).

  **This runs the *inbound* direction: GitHub → nucleus.** It confirms the premise of this
  spike: GitHub's OIDC is something *nucleus consumes to admit a workflow*, not something
  GitHub will accept to authorize a push. The push direction (nucleus identity → GitHub)
  has **no** OIDC path on GitHub's side — hence the GitHub App bridge in §2.

### 1.2 SVID issuance + the served-once workload-API provisioning pattern

- `crates/nucleus-identity/src/workload_api.rs` — the SPIFFE Workload API server; serves
  `FETCH_SVID` (X.509 SVID: cert chain + key) and `FETCH_BUNDLE` (trust bundle) to guests.
- `crates/nucleus-node/src/workload_api_vsock.rs` — the vsock transport of that API, and
  the home of the **served-once capability** discipline: `FETCH_TASK_TOKEN`,
  `FETCH_BROKER_SECRET`, `FETCH_AUDIT_CREDENTIALS`, `FETCH_DLC_ADMISSION`,
  `FETCH_POD_CALLER_TOKEN`. Repeat requests for a once-only capability are **refused**
  (see the `refused a repeat FETCH_BROKER_SECRET` / `FETCH_AUDIT_CREDENTIALS` arms).
- `crates/nucleus-node/src/workload_api_protocol.rs` — the command enum. **This is where a
  new `FETCH_GITHUB_TOKEN` variant slots in**, alongside the other per-pod capabilities.

### 1.3 The host-TCB secret model + the "host performs the call" pattern

- `crates/nucleus-cred-broker/src/lib.rs` — the **Credential Delivery Point (CDP)** of the
  CB4A architecture (draft-hartman-credential-broker-4-agents). It *holds* credentials and
  hands them to an already-approved request; it links against **no** policy crate (enforced
  by `deny.toml` + a manifest-reading test). **This is the correct home for the GitHub App
  private key and the installation-token minting logic** — policy-free credential custody.
  Status today: storage + separation invariant exist; **minting/injection not yet built**,
  so a GitHub-token minter would be a first concrete CDP consumer.
- `crates/nucleus-node/src/broker_perform.rs` — the **"host performs the outbound call so
  the guest never holds the credential"** pattern. On Firecracker the guest never receives
  `credentials.env`; the host makes the upstream call and returns only the *result*. This
  is the exact shape a "host performs the `git push` / GitHub API call" variant would take:
  the installation token need never enter the sandbox at all (see §2, variant B).
- `crates/nucleus-cred-protocol/src/lib.rs` — `TaskRequestEnvelope`, the signed request
  envelope the broker authenticates.

### 1.4 The IFC egress gate — the mediation this rides (the differentiator)

- `crates/nucleus-tool-proxy/src/egress.rs` — `credentialed_egress(...)`. This is the
  live, proven mediation point. At `egress.rs:286` it **mints a `DischargedBundle`** via
  `crate::run_gate::preflight_web(...)` before any credentialed outbound call, and only
  then asks the host to perform it (`portcullis_effects::authority::Authority::new(
  discharge_bundle)`). An un-preflighted egress is structurally impossible here.
- `crates/nucleus-tool-proxy/src/main.rs` — the declassification wiring a push would reuse:
  `credentialed_egress: Vec<CredentialedEgressSpec>` (line ~364), the authoritative
  `FlowGraph` egress verdict, and the k-of-n memory declassification
  (`declassify_trusted_keys`, `declassify_threshold`, fail-closed when unset).

  **A `git push` is modeled as one more `CredentialedEgressSpec` whose upstream is
  `github.com` / the API.** It flows through the *same* `preflight_web → DischargedBundle →
  host-performs` path, so the IFC boundary that this repo just finished proving governs the
  push for free. That composition is the whole point.

### 1.5 C9 "verify from the outside" (the external-verification tie-in)

- `docs/north-star.md:90` and `:280–298` — C9 is **NOT-YET**. `FETCH_SVID` serves a plain
  cert with no DICE attestation extension; `fetch_attested_certificate` is dead code and
  its result is discarded; no CA implements `sign_attested_csr`. The gitsign/Rekor
  attribution layer in §3 is a *second, independent* external-verification leg for C9:
  an outside party can confirm a commit came from an attested nucleus agent identity via
  the Rekor log entry, even before the SVID-embedded-measurement leg lands.

---

## 2. End-to-end flow

### 2.1 Auth (the push itself)

```
  agent (in Firecracker pod)
     │  1. FETCH_SVID  (workload_api_vsock.rs)  ── already exists
     ▼
  X.509 SVID: spiffe://<td>/ns/github/sa/{org}/{repo}
     │
     │  2. tool-proxy: agent requests "git push" as a
     │     CredentialedEgressSpec { upstream: api.github.com, ... }
     ▼
  crates/nucleus-tool-proxy/src/egress.rs :: credentialed_egress
     │  3. preflight_web(Operation::Push, scope, level, url, flow)  ── IFC GATE
     │     → mint DischargedBundle   (egress.rs:286)   [DENY ⇒ fail closed]
     ▼
  host / broker  (broker_perform.rs pattern)
     │  4. verify the DischargedBundle-authorized PerformRequest;
     │     verify per-pod broker secret (frame_is_authentic)
     │  5. cred-broker CDP: using GitHub App private key (HOST TCB),
     │     POST /app/installations/{id}/access_tokens
     │        → ghs_… installation token (≤1h, repo-scoped, least-priv)
     │  6. host performs the git/API push with that token
     ▼
  GitHub — commit lands under the App's per-agent identity
     (token never enters the sandbox; guest gets only the RESULT)
```

Two variants for step 5–6, pick per threat model:

- **Variant A — token injected into the pod** (like `FETCH_AUDIT_CREDENTIALS`): host mints
  the installation token and serves it once over `FETCH_GITHUB_TOKEN`; the pod runs `git
  push` locally. Simpler; the short-lived token briefly lives in the guest.
- **Variant B — host performs the push** (like `broker_perform.rs`, **preferred**): the
  token never enters the guest; the guest hands the host a *reviewed* pack/ref-update and
  the host pushes. Strongest containment; the credential is unreachable from a compromised
  guest. Recommended default.

The IFC gate (step 3) is identical in both variants: the push is only *composable* past a
minted `DischargedBundle`, so taint-to-sink is structurally blocked.

### 2.2 The GitHub App token mint (host side, standalone)

Standard GitHub App flow, entirely inside the host TCB:
1. Build a short (~10 min) **App JWT** signed by the App private key (RS256).
2. `POST /app/installations/{installation_id}/access_tokens` with a **least-privilege
   `permissions` body** and an explicit **`repositories` list** → returns a `ghs_…`
   installation token, **≤1h TTL**, scoped to those repos + permissions.
3. (2026 note) GitHub is rolling out a stateless `ghs_APPID_JWT` token format; no change to
   the mint call, but revocation semantics differ (see §5).

---

## 3. Verifiability / attribution + the honest "Verified" caveat

### 3.1 gitsign keyless signing bound to the SPIFFE identity

- gitsign signs commits with a **Fulcio** short-lived x509 cert carrying an OIDC identity,
  and logs the signature in **Rekor** (append-only transparency log). No long-lived key.
- **Fulcio has a native SPIFFE issuer type**: a SPIFFE JWT-SVID can be the OIDC token, and
  the resulting cert's **SAN is the SPIFFE ID**, scoped to the configured
  `SPIFFETrustDomain`. So a nucleus agent's commit signature is cryptographically bound to
  `spiffe://<td>/ns/github/sa/{org}/{repo}` — the *same* identity that authorized the push.

### 3.2 The honest caveats (state plainly)

1. **No native "Verified" badge.** GitHub's "Verified" badge requires a signature chaining
   to a key/identity in *GitHub's* trust store. The Fulcio root is not there, and the cert
   is ephemeral (valid ~10 min) — GitHub cannot re-validate it at view time. So these
   commits show **"Unverified"** (or no badge) in the GitHub UI. Verifiability is
   **out-of-band**: `gitsign verify` re-checks the cert + Rekor inclusion + validity at the
   *time of signing*. This is arguably *stronger* than the badge (transparency-logged,
   identity-bound, non-repudiable) but it is not what a casual reviewer sees. Do not imply
   the badge.
2. **Public Fulcio won't mint for an arbitrary trust domain.** To put a `spiffe://…` SAN in
   the cert you need a **self-hosted Fulcio + Rekor** with the SPIFFE issuer configured for
   your trust domain (public sigstore only trusts its allowlisted issuers). That is
   additional infrastructure the note must own, not hand-wave.
3. **nucleus emits X.509 SVIDs, not JWT-SVIDs today.** `FETCH_SVID` serves an X.509 SVID.
   Fulcio's OIDC path wants a **JWT** (JWT-SVID or an OIDC token whose `sub` is the SPIFFE
   ID). So a **JWT-SVID emission surface** (or a small OIDC token endpoint whose subject is
   the agent SPIFFE ID) is a prerequisite for the attribution layer — a real gap, not
   assumed present.

### 3.3 C9 tie-in

An external relying party can, given a commit, fetch the Rekor entry, confirm the signing
cert's SAN is a nucleus SPIFFE ID under the expected trust domain, and confirm the entry's
inclusion + signing-time validity — i.e. **verify from the outside** that the commit came
from an attested nucleus agent. This is a second, independent C9 leg alongside the
(still-unbuilt) SVID-embedded-measurement leg.

---

## 4. Minimal PoC sketch (smallest working demo)

Two independently demoable slices; ship them in order.

### Slice 1 — SVID → scoped GitHub App token (the auth core)

A tiny host-side broker endpoint (a first `cred-broker` CDP consumer):

```
  POST  (over the workload API / broker frame)   FETCH_GITHUB_TOKEN
  input : the pod's SVID (already established by the transport) + repo scope
  action: verify SVID  →  map SPIFFE ID → allowed installation+repos (policy is
          in the PDP, NOT the CDP)  →  build App JWT from the App private key
          (host TCB)  →  POST /app/installations/{id}/access_tokens with a
          least-privilege permissions body + explicit repositories list
  output: { token: "ghs_…", expires_at, repositories, permissions }   (served once)
```

Demo assertion: a pod with SPIFFE ID `…/sa/orgX/repoY` receives a token that can push to
`orgX/repoY` **and to nothing else** (a request for `repoZ` is refused), and the token
disappears within 1h. Regression guard: a test that the CDP crate still links no policy
crate (the existing manifest-reading test already does this), plus a scope-negative test.

### Slice 2 — gitsign against a self-hosted Fulcio using the SPIFFE identity

```
  1. stand up self-hosted Fulcio + Rekor; configure a SPIFFE issuer for
     trust-domain nucleus.local
  2. expose a JWT-SVID (or OIDC token with sub = the pod SPIFFE ID) — the one
     new emission surface
  3. configure gitsign:
        gitsign.fulcio        = <self-hosted Fulcio URL>
        gitsign.rekor         = <self-hosted Rekor URL>
        gitsign.connectorID / OIDC provider = the nucleus JWT-SVID endpoint
  4. agent commits;  gitsign verify <commit>  shows SAN = spiffe://nucleus.local/…
```

Demo assertion: `gitsign verify` on the resulting commit confirms the SPIFFE-ID SAN and a
valid Rekor inclusion proof — even though GitHub's UI shows "Unverified".

### Concrete near-term win (justifies the whole spike)

A **`nucleus-agent` GitHub App** with scoped enqueue/merge permissions, installed on this
repo, so agent PRs land under a **per-agent auditable App identity** instead of a shared
human account or a shared PAT. That directly de-frictions this repo's own merge workflow
(every DO-NOT-MERGE boot-gated PR today merges under a human) while being the first real
consumer of Slice 1. Merge/enqueue is itself a `CredentialedEgressSpec`, so it inherits the
IFC gate.

---

## 5. Risks / open questions

1. **App private-key custody.** The App key is a long-lived, high-value secret. It must live
   only in the host TCB (cred-broker CDP), never in a pod, never in an env var a workload
   can read. Rotation story? HSM / sealed-secret backing? An App key leak is catastrophic
   (mints tokens for every installation). This is the single biggest risk and argues for
   Variant B (host performs the push) so the key's blast radius never touches a guest.
2. **Token scoping + revocation.** Installation tokens are ≤1h and repo/permission-scoped —
   good. But the 2026 stateless `ghs_APPID_JWT` format changes revocation: a stateless token
   may not be individually revocable server-side the way a stateful one is. Confirm the
   revocation semantics before relying on "revoke on suspected compromise." Prefer the
   narrowest `permissions` + shortest lease acceptable.
3. **Per-agent installation vs one App.** One App with many installations, or one App and
   map SPIFFE ID → repo scope at mint time? One App + fine-grained per-mint scoping is
   simpler to operate and keeps the identity in the *token scope + gitsign cert*, not in a
   proliferation of Apps. But then the App identity is shared at the GitHub-audit-log level;
   per-agent attribution rests on the gitsign SAN + the nucleus-side mint audit, not on
   GitHub's actor field. Decide what "attribution" must mean to the relying party.
4. **Rekor privacy for private repos.** Rekor is a **public** transparency log. Signing
   commits to a *private* repo writes the commit hash + signer identity (the SPIFFE ID) to a
   public log. That may leak repo/branch structure and the existence of agent activity.
   Options: self-hosted private Rekor, or accept the leak, or sign only public-repo commits.
   Must be an explicit choice, not a default.
5. **Rate limits.** App JWT and installation-token endpoints have rate limits; a fleet of
   agents each minting per-push tokens can hit them. Cache/short-reuse installation tokens
   within their TTL per (installation, scope) rather than minting per commit.
6. **The JWT-SVID gap.** nucleus emits X.509 SVIDs; Fulcio wants a JWT. The JWT-SVID / OIDC
   emission surface is net-new and is a hard prerequisite for the attribution layer (Slice
   2). Slice 1 (auth) does **not** need it.
7. **Direction confusion.** `oidc.rs` is inbound (GitHub → nucleus). Reviewers will assume
   it is reusable for the push direction; it is not. The reusable surface for the push is the
   SVID + workload-API provisioning + cred-broker CDP, not `/v1/oidc/github`.

---

## 6. Corrections to the prior design

- **`oidc.rs` runs the *opposite* direction** from what the push needs. It is evidence *for*
  the "GitHub OIDC runs the other way" claim, but it is not the bridge — do not point a
  `FETCH_GITHUB_TOKEN` implementation at it. The bridge is App-key-in-CDP + mint.
- **The gitsign leg needs a self-hosted Fulcio + Rekor** configured with a SPIFFE issuer;
  the public sigstore instance will not mint a `spiffe://nucleus.local/…` SAN. The upside is
  real (Fulcio *natively* supports SPIFFE as a SAN type), but the infra cost and the
  private-repo Rekor-privacy question are load-bearing caveats, not footnotes.
- **A JWT-SVID (or SPIFFE-subject OIDC token) emission surface is a prerequisite** for
  attribution and does not exist yet; `FETCH_SVID` is X.509 only. Auth (Slice 1) is
  unaffected and can ship first.
- **Prefer Variant B (host performs the push)** over injecting the token into the pod: it
  matches the existing `broker_perform.rs` containment property and keeps the credential
  unreachable from a compromised guest.

## 7. References (2026 state)

- SPIFFE / SVID + broker API — https://spiffe.io/docs/latest/spiffe-about/overview/ ,
  https://spiffe.io/docs/latest/deploying/svids/ , JWT-SVID spec
  https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/
- SPIRE Identity Exchange (platform OIDC → SVID) — https://github.com/spiffe
- GitHub App installation tokens (short-lived, scoped; 2026 stateless `ghs_APPID_JWT`
  rollout) — https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app ,
  https://github.com/actions/create-github-app-token
- gitsign (keyless git signing, Fulcio + Rekor) — https://github.com/sigstore/gitsign ,
  https://www.chainguard.dev/unchained/keyless-git-commit-signing-with-gitsign-and-github-actions
- Fulcio OIDC + SPIFFE issuer / SAN — https://docs.sigstore.dev/certificate_authority/oidc-in-fulcio/ ,
  https://github.com/sigstore/fulcio/blob/main/docs/oidc.md
- CB4A (credential broker for agents) — https://datatracker.ietf.org/doc/draft-hartman-credential-broker-4-agents/
