# nucleus-oidc-provider — Operator Runbook

The OP is the cryptographic identity root for a nucleus mesh deployment. This document covers the four routine + emergency operator scenarios:

1. **Initial key-store bootstrap** (first deploy of a fresh OP)
2. **Routine key rotation** (planned, no incident)
3. **Federation rule deployment** (adding / updating rule entries)
4. **Incident response: signing-key compromise**

---

## 1. Initial key-store bootstrap

The first time the OP starts in a new environment, it has no `keystore.age` blob and no upstream-IdP verifying keys registered. Follow these steps in order.

### 1a. Decide on the passphrase source

Production: derive from KMS-unwrapped material at deploy time (do NOT type a passphrase into your shell). Recommended pattern:

```bash
# AWS KMS example — adapt to your KMS vendor.
PASSPHRASE=$(aws kms decrypt \
  --ciphertext-blob fileb://passphrase.ciphertext \
  --query Plaintext --output text | base64 -d)

flyctl secrets set NUCLEUS_OIDC_KEYSTORE_PASSPHRASE="$PASSPHRASE"
unset PASSPHRASE
```

Dev / staging: generate a 32-byte random passphrase, store in a password manager.

### 1b. Set the issuer URL

```bash
flyctl secrets set NUCLEUS_OIDC_ISSUER_URL=https://oidc.YOUR-DOMAIN.example/
```

The default in `fly.toml` is deliberately bogus to fail-loud on a forgotten override.

### 1c. Provision the persistent volume

```bash
flyctl volumes create nucleus_oidc_data --region iad --size 1
```

### 1d. First deploy

```bash
flyctl deploy
```

On first boot the OP creates a fresh `keystore.age` at `/data/keystore.age`. Tail the logs:

```bash
flyctl logs | grep -i bootstrap
```

You should see the active KID printed exactly once.

### 1e. Verify discovery + JWKS work

```bash
curl https://oidc.YOUR-DOMAIN.example/.well-known/openid-configuration | jq
curl https://oidc.YOUR-DOMAIN.example/jwks.json | jq
curl https://oidc.YOUR-DOMAIN.example/healthz | jq
```

`healthz` should show `ok: true`, `active_kid: "<43-char-thumbprint>"`, `verify_keys: 1`, `federation_rules: 0`.

### 1f. Load federation rules (see §3)

Without rules the OP returns `invalid_target` for every token-exchange — this is the default-deny posture from #41. Load rules before pointing real traffic at the OP.

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
```

Glob semantics: `*` suffix only (no regex, no anywhere-glob). Audience is exact match. See `crates/nucleus-oidc-provider/src/federation.rs` for the schema.

### 3b. Validate before deploy

```bash
# Locally:
cargo run --bin nucleus-oidc-provider -- --federation-rules-path ./oidc-federation.toml --dry-run
# TODO: wire up --dry-run flag. Until then, use the test:
cargo test -p nucleus-oidc-provider federation::tests::toml_round_trip_parses
```

`deny_unknown_fields` ensures typos fail-loud at parse.

### 3c. Deploy

Copy the file into the VM and SIGHUP to reload (when wired):

```bash
flyctl ssh sftp -a nucleus-oidc-provider <<< "put oidc-federation.toml /data/oidc-federation.toml"
# TODO: SIGHUP handler. Until then, restart:
flyctl machine restart -a nucleus-oidc-provider
```

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

- `GET /healthz` — JSON body: `{ok, active_kid, verify_keys, federation_rules}`. Wire to Fly health check (already in `fly.toml`).
- `flyctl logs` — structured tracing output. `RUST_LOG=info,nucleus_oidc_provider=debug` for deeper trace.
- Token-endpoint Deny events: `grep "federation: DENY"`.
- Replay rejections: `grep "subject_token .* already presented"`.

## Appendix B: Cross-references

- `crates/nucleus-oidc-provider/THREAT_MODEL.md` — T01..T13 threat catalog with mitigation → task index.
- `crates/nucleus-oidc-provider/fuzz/README.md` — fuzz harness CI integration.
- `crates/nucleus-oidc-provider/tests/key_rotation_properties.rs` — rotation invariants pinned by proptest.
- `docs/oidc-vendor-neutrality-audit.md` — what stays vendor-neutral vs platform-specific.
