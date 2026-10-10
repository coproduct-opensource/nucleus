# The OIDC provider's first tenant: what wiring it found (2026-10-08)

Owner decision, 2026-10-08: `nucleus-oidc-provider` gets its first tenant, olog's production app.
The trust domain is `coproduct.one` and the issuer is `https://oidc.coproduct.one`. The app's
machines exchange their platform OIDC token for a JWT-SVID with
`sub = spiffe://coproduct.one/ns/olog/sa/coproduct`, `aud = https://coproduct.one/admin` and
`scope = admin:data`, which olog's admin routes verify. Later, cloud workload-identity federation
should trust the same issuer.

The work found the following, measured on `origin/main` at `3eb5243d1`.

## 1. An issued token outlived its subject token, and `expires_in` said it did not

`JwtIssuer::mint` stamped `exp = iat + 300` (the issuer's configured lifetime) on every token. The
token endpoint computed `min(subject token's remaining life, rule's max_token_lifetime_secs)` and
reported it as `expires_in`, but never passed it to `mint`. A subject token with 60 s left therefore
bought a 300 s credential, and the response said 60. A rule's `max_token_lifetime_secs` below 300
bounded nothing. The module doc's "the response token never outlives the subject_token's exp" was
false.

Driven red on unmodified `main` by the test this change adds:

```text
token::tests::issued_exp_never_outlives_the_subject_token_and_matches_expires_in ... FAILED
issued token lives 300s; its subject token had 60s left
```

The fix: `MintRequest::not_after` (absolute) is required, so no call site can forget it. `mint`
decides `exp` once and returns it, and `expires_in` is read off the minted token (ADR 0007 G).
§10 tightens this further after review.

## 2. The binary never had a durable key or a way to load rules, and the runbook said it did

The wrong belief: "the OP is deployable by the runbook." `main` always built an `InMemoryKeyStore`
(a new EdDSA key on every restart) and `FederationRegistry::empty()`. The runbook's §1d ("on first
boot the OP creates a fresh `keystore.age`"), its passphrase step, and §3's
`--federation-rules-path` / SIGHUP reload described code that did not exist. An OP deployed by those
steps would have refused every exchange, with no way to load a rule. Every restart would also have
invalidated every token relying parties held. The runbook now describes the binary as it is.
`--signing-key-dir`, `--federation-config` and `keys {status,stage,promote,retire}` are new here.
Rules are read at start-up. There is still no reload signal, and the runbook says so.

## 3. EdDSA could not reach either relying party, so the provider gained ES256

- **Cloud workload-identity federation** accepts outside OIDC tokens "signed using the `RS256` or
  `ES256` algorithm" (Google Cloud IAM, *Workload Identity Federation with other providers*, read
  2026-10-08). EdDSA is not listed.
- **olog's verifier** (`coproduct-private/olog` `src/spiffe_auth.rs`, read 2026-10-08) builds
  `Validation::new(Algorithm::ES256)`. Its JWKS loader takes a key only as `pem` or as
  (`crv`, `x`, `y`). An Ed25519 OKP key has no `y`, so the provider's JWKS would have failed olog's
  whole trust-bundle load, not just one key.
- The SPIFFE JWT-SVID profile's algorithm list has no EdDSA.

There were two options. One was to add EdDSA verification to olog. That is a smaller diff, but it
helps only olog and leaves the cloud goal impossible. The other was to add ES256 to the provider,
which one change serves both with. The owner's coordinator chose the provider.

The provider adds no P-256 implementation of its own. `KeyringKeyStore` signs through
`nucleus-federation`'s keyring and `AssertionSigner`, ring's fixed-length P-256, and takes its
`alg` string from that crate's single `SIGNING_ALG` constant. T04 holds per deployment: a key store
has one `SigningAlg` (no `none`, HMAC or RSA variant), and `mint` refuses a signature whose
algorithm differs from the header.

## 4. A `debug_assert` was the only guard against a token naming the wrong key

`mint` reads the active `kid` for the header, then signs. The two were checked equal by
`debug_assert_eq!`, which a release build removes. With the in-process stores the race needed a
`rotate()` between two lines. With the keyring it is a promote by the operator in another process,
which is ordinary. It is now a real check with one retry (`JwtIssuerError::KeyChanged`), and the
signature's algorithm is checked the same way (`AlgMismatch`). Mutation evidence: making the keyring
store report EdDSA while signing ES256 turns three end-to-end tests red.

## 5. olog checks scope against its own policy, never against the token

olog authorizes by `policy.assert_grants(svid.sub, requested_scope)`, a `[[grant]]` table in its
`spiffe_authz.toml` keyed by SPIFFE ID. It never reads the token's `scope` claim. So the provider's
`max_scope = ["admin:data"]` is not what stops a token at olog. olog's grant for
`spiffe://coproduct.one/ns/olog/sa/coproduct` is. There are two deciders for one fact, and they can
drift. Recommended on olog's side: require the token's space-delimited `scope` to contain the scope
the route demands, in addition to the grant. The token then cannot be used for more than both
allow.

Other facts olog's side needs (its verifier as read on 2026-10-08):

- `iss` must be configured: its default is `spiffe://<trust domain>`, and this issuer's is
  `https://oidc.coproduct.one`.
- `exp − iat ≤ max_lifetime_seconds` (300), and the rule keeps tokens at ≤ 300 s.
- The trust bundle is a file today. olog is adding a load-by-URL path.

## 6. The platform's OIDC issuer, measured 2026-10-08

- `https://oidc.fly.io/coproduct/.well-known/openid-configuration`: `issuer` is exactly
  `https://oidc.fly.io/coproduct`, and `jwks_uri` is `…/.well-known/jwks`, with no `.json`.
- `id_token_signing_alg_values_supported` is `["RS256"]`. The JWKS holds one RSA key, 4096-bit,
  `alg RS256`, with a UUID `kid`.
- Claims: `sub` (`org:app:machine`), `aud`, `exp`, `iat`, `iss`, `jti`, `nbf`, `org_name`,
  `app_name`, `machine_name`, `org_id`, `app_id`, `machine_id`, `machine_version`, `region`,
  `image`, `image_digest`, `image_tag`.
- The platform's docs example has `exp − iat = 600`, and the request is
  `POST /v1/tokens/oidc {"aud": …}` on the `/.fly/api` socket.
- **Live probe.** The provider, started from the shipped config, was handed an RS256 token with the
  issuer's real `kid` and a random signature. The log read `outside issuer: token refused
  binding=olog-production reason=BadSignature`. That means the real discovery document passed the
  issuer pin, the `kid` resolved, and the RSA-4096 key was admitted for RS256.
- **Not verified:** whether `org_name` is the org's slug (the docs example suggests so). If it is a
  display name, every real token is refused with `reason=RequiredClaim`. That fails closed and
  shows up in the log. The `iss` path already pins the org either way.

## 7. Custody is a file, and that is said plainly

The platform's VMs have no TPM. `KeyCustody::File(NoTpmConfigured)` puts a `0400` PKCS#8 key on the
app's volume. Anyone with the volume or a snapshot holds the key. A KMS-held key, the preferred
custody, is another `AssertionSigner` implementation, and it was not built here for two reasons:

- It needs the machine to reach the KMS by workload identity. That means a pool and provider
  trusting the platform's issuer, and a KMS key with an IAM binding for it. Those are IAM changes,
  and they are the owner's to approve.
- Vendor-specific KMS client code may not live in this crate (`ci/no-vendor-strings.sh`). It
  belongs in a sibling crate.

The keyring's rotation protocol (stage → promote after 75 min → retire after 65 min) is the same
for either custody.

## 8. The platform chowns a volume's mount point to the image's user (reported, not measured)

The platform's staff state this in its community forum. It is what makes `/data/keys` writable by
distroless `nonroot`, which is also the owner the keyring demands of every key file. Not measured
here, because there was no deploy. If it is wrong, the OP fails at start with `creating /data/keys`
and never runs with a key it cannot protect. A `keys` step run as root is refused by the keyring
(the temp file's owner is not the directory's), so the runbook says `ssh console -u nonroot`.

## 9. A citation to a section that does not exist

`fly.toml` said "Architecture per `nucleus/CLAUDE.md` Fly.io section". `CLAUDE.md` has no such
section, and no findings mandate either. The brief for this work cited both. The citation is
replaced with the runbook. Dated notes under `docs/findings/` are the place this repository already
keeps what a change found.

## 10. An independent review found a replay bypass, and three more

A review agent read the change before the PR (2026-10-08). What it found, and what was done:

- **High, reproduced: ECDSA malleability bypassed the outside-issuer replay cache.**
  `ExternalIssuerValidator` keyed replay on SHA-256 of the whole compact token. An ECDSA signature
  `(r, s)` also verifies as `(r, n − s)`, and anyone holding the token can compute that without the
  key. So a captured ES256 or ES384 outside token hashed as new and could be exchanged again until
  its `exp`. This was latent in nucleus-node's federation ingress (#3022) too, since it uses the
  same validator.
  - Red on the old code: `a_token_with_its_ecdsa_signature_flipped_is_still_a_replay` saw the
    flipped token accepted.
  - The replay key is now the hash of the signed content. `ValidatedCaller::token_hash` (the whole
    token) stays the provenance a delegation certificate records.
  - **Corrected assumption:** `a_refused_token_does_not_occupy_the_replay_cache` treated "the same
    claims, re-signed" as a distinct token. Under content keying it is the same token, so the test
    now varies the claims.
  - The RS256 binding shipped here was not exposed: PKCS#1 v1.5 signatures are deterministic.
- **Medium-low: an issued token could start past its subject token's `exp`.** The outside
  validator admits a token until `exp + leeway`, and a 1 s lifetime floor then minted
  `exp = now + 1`. Separately, `mint` re-read the clock, so `exp` could exceed the subject's by 1 s
  on either path. Now:
  - `MintRequest::not_after` is absolute, and `mint` refuses a token with no life left instead of
    flooring it.
  - `expires_in` is read off the minted token.
  - The outside path refuses at `exp`, as the SPIFFE path does.
  - Red under the pre-review semantics:
    `a_token_inside_the_leeway_but_past_exp_is_refused`.
- **Low-medium: a binding could name the OP's own issuer.** That would route the OP's own tokens to
  one fixed identity. It is now refused at load, with the trailing slash ignored, and driven red by
  removing the guard. An outside-path token is now stamped
  `urn:nucleus:kind = "outside_token_exchange"`.
- **Low: `/jwks.json` parsed private key files on every unauthenticated request.** The published
  set is now cached for 5 s. Signing still reads the current key every time (ADR 0007 C-1).
- **ADR 0007:**
  - `leeway_secs` was defaulted (B). It is now required.
  - `OutsideIssuers::build` re-decided what `parse_toml` decides (G). It now calls the same
    validator.
- **Accepted, recorded:**
  - The 503 for unreachable outside keys can only arise for a bound `iss`, so it reveals which
    issuers are bound. That is not secret, and the bodies stay opaque.
  - A discovery-document issuer mismatch answers 400 like any refusal, not 503. It is a
    misconfiguration that a caller cannot fix by retrying.

## Not done here

- **No deploy.** The only credential on the operator's Mac is a person's interactive platform
  login. Automation must not use it, and no app-scoped deploy token exists.
- **No end-to-end exchange with a real platform token.** That needs a running machine of the app.
- **Cloud workload-identity federation is untried.** The discovery document's
  `response_types_supported` is `[]`. If the cloud's validator wants a value, it will say so on the
  first pool-provider creation.
