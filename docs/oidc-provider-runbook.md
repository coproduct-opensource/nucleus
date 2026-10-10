# nucleus-oidc-provider — Operator Runbook

The OP is the cryptographic identity root for a nucleus mesh deployment. This document covers the four routine + emergency operator scenarios:

1. **Initial key-store bootstrap** (first deploy of a fresh OP)
2. **Routine key rotation** (planned, no incident)
3. **Federation rule deployment** (adding / updating rule entries)
4. **Incident response: signing-key compromise**

---

## 1. Initial key-store bootstrap

**Corrected 2026-10-08.** This section used to describe a `keystore.age` blob created on first
boot, with its passphrase from a secret, and §3 a `--federation-rules-path` flag. Neither existed:
`main` always started an in-memory EdDSA key (gone on restart) and an empty rule set, and nothing
could load rules. An OP deployed by the old steps would have served a key that changed on every
restart and refused every exchange. What follows is what the binary does
(`docs/findings/oidc-provider-first-tenant.md` §2).

### 1a. Choose the signing algorithm, which chooses the key store

| | `--signing-key-dir` set | not set |
|---|---|---|
| algorithm | **ES256** | EdDSA |
| key store | `KeyringKeyStore`: `nucleus-federation`'s keyring directory | `InMemoryKeyStore`: lost on restart (dev only) |
| rotation | `nucleus-oidc-provider keys {stage,promote,retire}` (§2E) | in process |
| relying parties | anything that takes an outside OIDC issuer: cloud workload-identity federation (RS256/ES256 only), SPIFFE JWT-SVID verifiers | nucleus-aware relying parties only |

Use ES256 whenever a token leaves the mesh. The OP signs exactly one algorithm. Discovery, the JWKS
and `/healthz` (`signing_alg`) all name it (THREAT_MODEL T04).

### 1b. Key custody: say what it is

The keyring's custody is a `KeyCustody`. On a host with no TPM, which is every platform VM this
runbook deploys to, the key is `File(NoTpmConfigured)`: a `0400` PKCS#8 file in
`--signing-key-dir`, owned by the directory's owner. **It is not sealed.** Anyone holding the volume,
or a snapshot of it, holds the key. No passphrase is involved, so there is nothing to type and
nothing to fetch from a KMS. The volume's at-rest encryption is the platform's.

A TPM- or KMS-held key needs no change here: it is another implementation of
`nucleus_federation::AssertionSigner`, the trait the keyring signs through (ADR 0009, ADR 0012). A
KMS signer (e.g. a cloud KMS `EC_SIGN_P256_SHA256` key with `asymmetricSign`, the result verified
locally before use) belongs in a sibling crate that names its vendor, never in this one.

### 1c. Set the issuer URL, and do not change it later

`NUCLEUS_OIDC_ISSUER_URL` is written into every token as `iss`. Relying parties compare it byte for
byte, and an outside issuer's tokens must carry it as `aud`. Pick the final hostname before the
first relying party is configured. Use no trailing slash, because `https://x` and `https://x/` are
different issuers. A custom hostname needs DNS pointing at the app and a certificate for it.

### 1d. Provision the volume, then deploy

```bash
flyctl volumes create nucleus_oidc_data --region iad --size 1
flyctl deploy . --config crates/nucleus-oidc-provider/fly.toml \
  --dockerfile crates/nucleus-oidc-provider/Dockerfile        # from the repository root
```

The volume's mount point is owned by the image's user (distroless `nonroot`), so on first boot the
OP creates `--signing-key-dir` (`0700`) and its first key (`0400`). The log says so once:

```text
keyring: created the first signing key kid=<43-char thumbprint>
signing ES256 with the keyring's current key active_kid=<same>
federation config loaded rules=<n> outside_issuers=<n>
```

A key directory whose key fails its checks (mode, owner, parse), or holds the other custody's
layout, stops the OP from starting. It does not replace a key that relying parties trust.

### 1e. Verify discovery + JWKS work

```bash
curl https://oidc.YOUR-DOMAIN.example/.well-known/openid-configuration | jq
curl https://oidc.YOUR-DOMAIN.example/jwks.json | jq
curl https://oidc.YOUR-DOMAIN.example/healthz | jq
```

`healthz` should show `ok: true`, `signing_alg: "ES256"`, `active_kid` (43 characters),
`verify_keys: 1`, and the `federation_rules` / `outside_issuers` counts you deployed. The JWKS entry
is `{"kty":"EC","crv":"P-256","x":…,"y":…,"kid":…,"alg":"ES256","use":"sig"}`.

### 1f. Load federation rules (see §3)

Without rules the OP returns `invalid_target` for every token exchange. This is the default-deny
posture from #41. `--federation-config` (`NUCLEUS_OIDC_FEDERATION_CONFIG`) names the TOML file, and
a file that does not parse or validate stops the OP from starting.

---

## 2. Routine key rotation

The OP supports planned rotation with a 1h grace window — tokens signed by the previous key remain verifiable for 1h after rotation, then auto-evict.

### 2a. Cadence recommendation

- **Quiet steady state:** rotate every 7 days.
- **High-volume / regulated:** rotate every 24h.
- **Incident:** rotate immediately (see §4).

### 2b. Initiate

For now the rotation primitive is in-process — the `KeyRotator` (#37) runs on a configurable cadence. To rotate ad-hoc:

```bash
# SSH onto the running VM and send SIGUSR1 — TODO: wire up this signal handler
# (currently the rotation cadence is configured at startup and runs on a
#  background tokio task).
flyctl ssh console -a nucleus-oidc-provider
# Inside: kill -USR1 1   # TODO once handler is wired
```

In the meantime, restart the VM after updating the rotation cadence in `main.rs`:

```bash
flyctl deploy --strategy=rolling
```

### 2c. Verify

```bash
# JWKS should now show 2 keys (active + grace-window).
curl https://oidc.YOUR-DOMAIN.example/jwks.json | jq '.keys | length'   # 2

# After 1h grace window expires, only 1 key remains.
sleep 3700 && curl https://oidc.YOUR-DOMAIN.example/jwks.json | jq '.keys | length'   # 1
```

### 2d. Operator alert if grace window doesn't drain

If after 2 × grace_window the verify-set is still > 1, the sweep loop is stuck. Restart the VM:

```bash
flyctl machine restart -a nucleus-oidc-provider
```

### 2E. ES256 (`KeyringKeyStore`): stage, promote, retire

The keyring does not swap keys at once, because a relying party that cached the JWKS just before
would see a `kid` it does not have. Run each step as the key directory's owner: a file written by
anyone else is refused, which is the safe direction because it fails before the server could be
handed a key it cannot read. On the platform VM that means
`flyctl ssh console -u nonroot -C "/app/nucleus-oidc-provider keys <step>"`.

```bash
nucleus-oidc-provider keys status    # published kids; when promote / retire become allowed
nucleus-oidc-provider keys stage     # next key: published from now, never signs
# ≥ 75 min later (JWKS cache 15 min + longest token 60 min):
nucleus-oidc-provider keys promote   # next becomes current; the OP signs with it at once, no restart
# ≥ 65 min later (longest token + 5 min skew):
nucleus-oidc-provider keys retire    # previous key leaves the JWKS
```

The running OP reads the directory on every signature and every JWKS request, so no restart is
needed. `rotate()` and `revoke()` on this store answer `OperatorRotated`. The emergency path is §4E.

---

## 3. Federation rule deployment

Federation rules declare which `(subject_prefix, audience, allowed_grants, max_token_lifetime)` quadruples are permitted. Empty rule set = default-deny.

### 3a. Author the rules file

`oidc-federation.toml`:

```toml
[[rule]]
id = "agents-to-vault"
subject_prefix = "spiffe://YOUR-TRUST-DOMAIN/ns/production/*"
audience = "https://vault.YOUR-DOMAIN.example/v1/auth"
allowed_grants = ["urn:ietf:params:oauth:grant-type:token-exchange"]
max_token_lifetime_secs = 3600

[[rule]]
id = "agents-to-kms"
subject_prefix = "spiffe://YOUR-TRUST-DOMAIN/ns/production/*"
audience = "https://kms.YOUR-DOMAIN.example/v1/sign"
allowed_grants = ["urn:ietf:params:oauth:grant-type:token-exchange"]
max_token_lifetime_secs = 300
max_scope = ["sign:release"]
```

### `max_scope` — what the token may DO once it arrives

The three fields above bound **who** may reach **which** audience and **for how
long**. `max_scope` bounds **what the issued token may do when it gets there**,
and it is the field to set deliberately.

Before it existed, `scope` was echoed from the request verbatim: a workload
asked for a scope and the OP minted it. Nothing downstream enforces on our
`scope` today, which made it inert rather than dangerous — but it is precisely
the claim a relying party keys on, and the moment one does, an unbounded scope
is an unbounded credential.

| `max_scope` | meaning |
|---|---|
| absent | the rule bounds no scope. A request that **asks** for one is refused; a request that asks for none is unaffected. |
| `max_scope = []` | constrained to nothing: no scope may be requested. Distinct from absent. |
| `max_scope = ["a", "b"]` | the requested scope must be a **subset**. A caller may ask for less; never for more. |

Narrowing only, and **refused rather than trimmed**: a caller asking for
`sign:release sign:anything` under the rule above gets an error, not a token
that quietly does half of what they asked. A credential that silently means less
than its holder believes is its own class of incident.

The caller sees a bare `invalid_target`. Which scopes the rule admits is
operator information — answering it would make the token endpoint a policy
oracle a caller could enumerate — so **the refused scopes and the ceiling go to
the log**, at `WARN`, with the rule id. That is where to look when a workload
reports a denial you did not expect.

Absent is the migration-safe default rather than the fail-closed one, and the
distinction is worth understanding: fail-closed on the *hazard* (an unbounded
scope being minted) costs nothing, because a request for no scope still
succeeds under every rule. Set `max_scope` on every rule whose RP looks at
scope at all.

### `scope_requires` — what the PRINCIPAL delegated

`max_scope` is the operator's ceiling: what this rule is willing to issue.
`scope_requires` is the principal's: what the person who approved *this pod's*
grant actually delegated. Both have to hold.

```toml
[[rule]]
id = "agents-to-logs"
subject_prefix = "spiffe://YOUR-TRUST-DOMAIN/ns/production/*"
audience = "https://logs.YOUR-DOMAIN.example/v1"
allowed_grants = ["urn:ietf:params:oauth:grant-type:token-exchange"]
max_token_lifetime_secs = 900
max_scope = ["logs:read", "logs:write"]

[rule.scope_requires]
"logs:read"  = ["aws/read-logs"]
"logs:write" = ["aws/write-object"]
```

The map is a **translation**, and it has to be: a relying party's scopes are its
own (`logs:read`), nucleus's effects are the units a person granted
(`aws/read-logs`). The rule is the one place that knows both, which makes it the
one place an operator can be asked to state the correspondence deliberately
rather than have it guessed.

A workload presents its pod certificate as the RFC 8693 `actor_token`:

```
actor_token=<base64 AttenuationToken>
actor_token_type=urn:nucleus:params:oauth:token-type:pod-certificate
```

`actor_token` is the slot for "the party acting on the subject's behalf", and a
pod certificate is exactly that: the signed, attenuating record of what a person
delegated to this workload. It is not a JWT and does not need to be — RFC 8693
lets a token type be any URI.

The rule above then issues `logs:write` only to a pod whose certificate grants
`aws/write-object`. **The operator's ceiling and the principal's grant both
apply**, and the delegation ceiling survives the boundary — which is the thing
SPIFFE alone does not give you. SPIFFE says *who this workload is*; the
certificate says *what its principal allowed*.

A scope with no `scope_requires` entry is bounded by `max_scope` alone, so the
feature is opt-in per scope and adding it breaks nothing.

#### `NUCLEUS_OIDC_CERT_ROOT_PUBKEY` is not optional if you use this

Set it to the hex of the 32-byte Ed25519 root your pod certificates chain to.

**Why it is load-bearing.** `AttenuationToken::verify` walks the chain against
the root key *the token itself carries*, which proves the chain is internally
consistent and nothing else — anyone can generate a root and mint themselves a
certificate granting `aws/mutate-iam`. The pinned root is the only thing that
makes a presented certificate mean anything, and it is compared in constant time
before the chain is walked at all.

An OP with no pinned root refuses every certificate, so a rule using
`scope_requires` will deny rather than fall back to the operator ceiling. That
is the intended failure direction: a misconfigured OP issues nothing rather than
issuing something it cannot justify.

#### What the relying party receives

When a certificate was verified, the issued token carries the granted effects:

```json
{
  "sub": "spiffe://prod.example.com/ns/agents/sa/coder",
  "aud": "https://logs.YOUR-DOMAIN.example/v1",
  "scope": "logs:read",
  "act": { "sub": "spiffe://prod.example.com/ns/agents/sa/coder" },
  "urn:nucleus:effects": ["aws/read-inventory", "aws/read-logs"]
}
```

An RP that understands nucleus can enforce per-effect from the token alone. One
that does not ignores a namespaced private claim it has never heard of (RFC 7519
§4.3), and the `scope` it does understand is already bounded by those effects.

**`urn:nucleus:effects` absent means "not established", never "none".** An
exchange with no certificate omits the claim rather than asserting an empty
grant. An RP that read the first as the second would conclude a workload had
been delegated nothing, when in fact nobody had said either way.

Glob semantics: `*` suffix only (no regex, no anywhere-glob). Audience is exact match. See `crates/nucleus-oidc-provider/src/federation.rs` for the schema.

### 3a′. `[[outside_issuer]]`: tokens from an issuer nucleus does not run

A workload on a platform with its own OIDC issuer has no SPIFFE JWT-SVID to present, but it has
that issuer's token. A binding exchanges such a token as **one** SPIFFE ID, and from there the rules
above apply to it like any other subject:

```toml
[[outside_issuer]]
id = "build-runners"
issuer = "https://idp.example/tenant-a"      # exact `iss`; dispatch is by this string
algs = ["RS256"]                              # what the issuer signs with; no none/HMAC/EdDSA
jwks = "discovery"                            # or { uri = "https://idp.example/keys" }
max_lifetime_secs = 3600                      # largest exp − iat accepted (≤ 24 h)
leeway_secs = 30                              # required (never defaulted), ≤ 60
spiffe_id = "spiffe://example.org/ns/ci/sa/runner"
[outside_issuer.required_claims]              # REQUIRED, non-empty; exact string match
tenant = "tenant-a"
workload = "runner"
```

The binding sets what the token must carry. The validator checks it with
`nucleus_federation::ExternalIssuerValidator`, the same checks as the node's federation ingress
(#3022):

- **`aud` is this OP's issuer URL.** It is not configurable. The workload requests its token with
  that audience.
- The algorithm is in `algs` and fits its key.
- The token has not been presented before. Replay is keyed on the token's hash.
- With `jwks = "discovery"`, the discovery document's `issuer` must equal `issuer` byte for byte.

The binding refuses to load if:

- `required_claims` is empty. An issuer serves many workloads, and naming none would give
  `spiffe_id` to all of them.
- `spiffe_id` is a prefix or a wildcard.
- The issuer is bound twice.
- The issuer is this OP's own issuer URL.
- `leeway_secs` is absent.

A token past its `exp` is refused even inside the leeway, the same line the SPIFFE path holds. The
issued token is stamped `urn:nucleus:kind = "outside_token_exchange"`, not `"token_exchange"`, so a
relying party can tell an identity a binding granted from one a workload's own SVID proved.

The binding grants an identity and nothing else. Audience, grant, lifetime and `max_scope` come from
a `[[rule]]` naming that SPIFFE ID. Refusals reach the caller as the same opaque `invalid_grant`.
The log says which check failed (`outside issuer: token refused binding=<id> reason=<Check>`). An
issuer whose keys cannot be fetched answers `503 temporarily_unavailable` so the caller retries.

The coproduct.one deployment's config is `crates/nucleus-oidc-provider/deploy/federation.coproduct-one.toml`.
The Dockerfile copies `deploy/` into the image at `/app/deploy/`, so the rules a running OP enforces
are part of its image digest.

### 3b. Validate before deploy

```bash
# Start it locally against the file. A config that does not validate exits non-zero before binding.
cargo run -p nucleus-oidc-provider -- --bind 127.0.0.1:18080 \
  --issuer-url https://oidc.YOUR-DOMAIN.example --signing-key-dir "$(mktemp -d)/keys" \
  --federation-config ./oidc-federation.toml
curl -s 127.0.0.1:18080/healthz | jq '{federation_rules, outside_issuers}'
```

A shipped deployment config also has a test that loads it the way `main` does
(`tests/outside_issuer.rs`, `the_shipped_coproduct_one_config_loads_and_grants_only_admin_data`).

`deny_unknown_fields` ensures typos fail-loud at parse.

### 3c. Deploy

Rules are read once at start-up. There is no reload signal. Change the file under `deploy/` and
redeploy (§1d): the new image carries the new rules, and the deploy record says when they changed.

### 3d. Audit-log diff

Every Deny is logged at `tracing::warn` level with the matched-rule-id (or `no_match`). After deploy, monitor:

```bash
flyctl logs -a nucleus-oidc-provider | grep "federation: DENY"
```

A spike in Denies after a rule change usually means a rule was tightened too far — re-deploy the previous version.

---

## 4. Incident response: signing-key compromise

If you suspect or confirm that the active signing key has been exfiltrated:

### 4a. Triage (within 5 minutes)

- **Don't rotate yet** — rotation keeps the compromised key in the grace window. Use **revoke** (see step 4c).
- Snapshot the current JWKS so you have a record of what was active:

  ```bash
  curl -s https://oidc.YOUR-DOMAIN.example/jwks.json > /tmp/jwks-pre-incident.json
  ```

- Notify downstream RPs out of band (Slack, PagerDuty) — every issued token from this key may be compromised.

### 4b. Rotate to a new active key

```bash
# Force a rotation (TODO: when SIGUSR1 handler lands)
flyctl machine restart -a nucleus-oidc-provider  # interim
```

Verify the new active KID is different from the snapshot.

### 4c. Revoke (NOT just rotate) the compromised key

The `revoke` endpoint removes the key from the verify-set IMMEDIATELY with no grace window. Tokens signed by the compromised key stop verifying as soon as RPs refresh their JWKS cache (typically 5 min per the `max-age=300` Cache-Control header).

```bash
# TODO: expose `revoke` as an admin HTTP endpoint or CLI command.
# Until then, manual procedure:
# 1. flyctl ssh console -a nucleus-oidc-provider
# 2. cargo run --bin nucleus-oidc-provider -- revoke --kid <compromised-kid>
```

### 4E. ES256 (`KeyringKeyStore`): replace the key outright

The keyring has no `revoke`: its stage/promote protocol waits for caches on purpose, which is the
wrong speed during a compromise. Replace the key instead:

```bash
curl -s https://oidc.YOUR-DOMAIN.example/jwks.json > /tmp/jwks-pre-incident.json
flyctl ssh console -a nucleus-oidc-provider -C "rm -f /data/keys/jwt_svid_p256_signing_key.der \
  /data/keys/jwt_svid_p256_signing_key.next.der /data/keys/jwt_svid_p256_signing_key.prev.der \
  /data/keys/jwt_svid_p256_rotation.json"
flyctl machine restart -a nucleus-oidc-provider
```

From the moment the files are gone, every signature fails closed. The signer never falls back to a
key it no longer finds. On restart the OP creates a fresh key, and the JWKS publishes only that one.
Every token the old key signed stops verifying as relying parties refetch the JWKS (`max-age=300`).
Confirm the new `active_kid` differs from the snapshot.

### 4d. Force-refresh downstream caches

Most RPs respect `Cache-Control` and will pick up the new JWKS within 5 min. For urgent cases:

- Bump the discovery doc's etag (forces RPs that pin etags to re-fetch).
- Direct outreach: hit each RP's "refresh JWKS" admin endpoint if one exists.

### 4e. Post-incident

- File a post-mortem; the threat-model docs `T01` mitigation list is the runbook checklist.
- Audit the operator credentials that could have leaked the keystore passphrase — those are the practical attack surface, not the keystore itself.
- Rotate the passphrase (`flyctl secrets set NUCLEUS_OIDC_KEYSTORE_PASSPHRASE=...` with a fresh value).

---

## Appendix A: Observability

- `GET /healthz` — JSON body: `{ok, active_kid, verify_keys, federation_rules, bundle_keys, outside_issuers, signing_alg}`. Wire to Fly health check (already in `fly.toml`).
- `flyctl logs` — structured tracing output. `RUST_LOG=info,nucleus_oidc_provider=debug` for deeper trace.
- Token-endpoint Deny events: `grep "federation: DENY"`.
- Replay rejections: `grep "subject_token .* already presented"` (JWT-SVIDs); outside issuers log `reason=Replayed`.
- Outside-issuer decisions: `grep "outside issuer:"`. An accepted token logs the binding, the outside `sub` and the SPIFFE ID it became.

## Appendix B: Cross-references

- `crates/nucleus-oidc-provider/THREAT_MODEL.md` — T01..T13 threat catalog with mitigation → task index.
- `crates/nucleus-oidc-provider/fuzz/README.md` — fuzz harness CI integration.
- `crates/nucleus-oidc-provider/tests/key_rotation_properties.rs` — rotation invariants pinned by proptest.
- `docs/oidc-vendor-neutrality-audit.md` — what stays vendor-neutral vs platform-specific.
