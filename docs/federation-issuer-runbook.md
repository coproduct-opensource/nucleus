# Federation issuer — operator runbook

A node with `--federation-issuer` signs short ES256 assertions that its pods' upstream
credentials are exchanged for (ADR 0010; the wire contract is
`docs/federated-upstream-profile.md`). A provider accepts them only if it knows this issuer's
keys and has a rule saying which assertions map to which of its principals. This runbook covers:

1. publishing the issuer (static hosting, or an inline JWKS);
2. the provider rule to register, and (2a) requiring an attested node;
3. rotating the signing key without a refused assertion;
4. what failure looks like.

Every command runs **on the node host, as the node's user**, and reads the node's own
environment variables (`NUCLEUS_NODE_STATE_DIR`, `NUCLEUS_FEDERATION_ISSUER`,
`NUCLEUS_NODE_UPSTREAMS`), so in that environment the flags below can be left off. No
command prints private key material.

The key lives in the state directory:

| file | role |
|---|---|
| `jwt_svid_p256_signing_key.der` | current: the node signs with it |
| `jwt_svid_p256_signing_key.next.der` | staged: published, never used to sign |
| `jwt_svid_p256_signing_key.prev.der` | previous: published until its last assertion expired |
| `jwt_svid_p256_rotation.json` | when each was staged or promoted, keyed by `kid` |

All are mode `0400`, owned by the state directory's owner. The node and the CLI refuse a key
file with group or other permission bits, a different owner, or a symlink. Rotation also
refuses a state directory that group or others can write.

**On a node with a TPM (`--node-evidence-tpm`), the key lives in the TPM** (ADR 0012). The
node creates it there, bound by a `PolicyPCR` to the boot PCRs 0, 2, 4, 7, 8, 9 and 14, and
the state directory holds only the TPM's wrapping of it:
`jwt_svid_p256_tpm_key.json`, `.next.json` and `.prev.json`, in the same three roles as
above. A copy of the disk cannot sign: the blob loads only in this TPM, and signs only while
the boot state matches. The AK certifies each published key every epoch, and the node keeps
the statements at `node-evidence/federation-keys.json` (also `GET /v1/node/federation-keys`).
`issuer --export` copies them beside the JWKS as
`.well-known/nucleus-federation-key-attestation.json`, and a relying party checks them with
`nucleus-audit verify-node-evidence --jwks … --federation-key-attestation …`.

- **Stage with the TPM:** `nucleus federation rotate --stage --tpm /dev/tpmrm0`. Promote and
  retire are renames and need no TPM.
- **An upgrade changes the key.** A new kernel, initrd, boot loader or command line is a new
  boot state. At its first start in that state the node finds its key unusable, logs it, and
  creates a new current key. Upstreams must be told about it, as after any key loss: publish
  the new JWKS before relying on federation again. Signed policies, which would avoid this,
  are a follow-up (ADR 0012).
- **A file key on a node with a TPM** needs `--allow-federation-key-in-file`. The node logs
  the waiver at start-up, and every custody statement it publishes says "file" and why. There
  is no conversion between the two layouts. A directory of the wrong custody stops the node:
  move it aside to start over with a new key.
- **The node's Ed25519 keys are sealed too** (executor, approval, certificate root, task
  issuer; ADR 0012, addendum A2). On a node with `--node-evidence-tpm` each one is sealed to
  the same boot PCRs as `<role>_signing_key.sealed.json` and unsealed into memory at start-up.
  The first start with a TPM migrates existing `.der` files in place with the **same public
  keys**: it seals each key, unseals what it wrote to check it, and only then deletes the
  file. `GET /v1/node/key-custody` says which keys are sealed and under which policy. This
  protects the keys at rest only: the running node holds them in RAM. Its own waiver is
  `--allow-node-keys-in-file`, independent of the federation key's, so a node can keep a
  file federation key and still seal its node keys. After an upgrade of the bound boot chain,
  each node key is a new key: the old blob is kept as `….sealed.json.unusable-<time>`.

## 1. Publish the issuer

Pick one. A provider that supports discovery or a JWKS URL should get one of those: an inline
JWKS has to be re-registered by hand at two points in every rotation.

**Static hosting (discovery).** The issuer URL must serve two files over https:

```bash
nucleus federation issuer --issuer https://federation.nodes.example.invalid \
    --state-dir /var/lib/nucleus-node --export ./site
# ./site/.well-known/openid-configuration   issuer = exactly the --issuer string
# ./site/.well-known/jwks.json              jwks_uri = <issuer>/.well-known/jwks.json
```

Upload `./site` so that `<issuer>/.well-known/openid-configuration` and
`<issuer>/.well-known/jwks.json` resolve. The `issuer` in the document is copied byte for byte;
it must equal the node's `--federation-issuer` exactly (a trailing slash counts), because
providers compare it to every assertion's `iss`.

**Inline JWKS.** Print it and paste it into the provider's issuer registration:

```bash
nucleus federation issuer --state-dir /var/lib/nucleus-node --jwks
```

## 2. The provider rule

```bash
nucleus federation issuer --issuer https://federation.nodes.example.invalid \
    --claims-for model-api --upstreams /etc/nucleus/upstreams.toml \
    [--tenant tenant-a.example.invalid]
```

It prints the matchers: exact `iss`, exact `aud` (the registry entry's
`[upstream.credential.federated] audience`), `nucleus_upstream` = the entry's name, and
`nucleus_tenant` if given. Register all of them.

Every pod on a node signs under the same `iss`. A rule on `iss` alone, or on a `sub` prefix,
matches **every pod on the node** (THREAT_MODEL T05). Do not match on `sub`: it is a per-pod
SPIFFE ID. The node's own mint decision is the real gate; the rule is a second one.

## 2a. Requiring an attested node

Every assertion states the node's platform tier and names the evidence epoch it rests on
(`nucleus_att_tier`, `nucleus_att_epoch`, `nucleus_att_time`, `nucleus_evidence_digest`;
profile §8, ADR 0012 addendum A3). The tier is the node's own appraisal of the evidence in
force at each mint, so the node needs the same inputs a relying party would use:

```bash
nucleus-node … --node-evidence-tpm /dev/tpmrm0 \
    --node-evidence-anchor operator:<source> \
    --node-evidence-ak-pin <SHA-256 of the AK SubjectPublicKeyInfo, as fetched from <source>> \
    --node-evidence-reference /etc/nucleus/node-reference.json
```

Without `--node-evidence-reference` every assertion says `unattested` (and still names the
epoch). Without a TPM it says `unattested` and `none`. Both flags are flags only, never
environment variables.

**Before registering the issuer with a rule on the tier**, check that its keys are in the
TPM, or the tier claim is worth nothing:

```bash
nucleus-audit verify-node-evidence --evidence <epoch evidence> --reference <reference> \
    --executor-ed25519 <executor key> --federation <SHA-256 of the JWKS> \
    --receipt-time "$(date +%s)" --operator-pin <source>=<pin> \
    --jwks jwks.json --federation-key-attestation nucleus-federation-key-attestation.json
```

It must exit 0: `Attested`, and every key `tpm_bound`.

**A workload-identity pool provider that evaluates CEL.** For example, with the `gcloud`
CLI, a provider that issues a token only for a fresh `attested` assertion from one upstream
entry (`model-api` here; the condition after the first `&&` is the profile's §8 condition,
verbatim):

```bash
gcloud iam workload-identity-pools providers create-oidc nucleus-node-attested \
    --project=PROJECT_ID --location=global --workload-identity-pool=POOL_ID \
    --issuer-uri=https://federation.nodes.example.invalid \
    --allowed-audiences=AUDIENCE_FROM_THE_REGISTRY_ENTRY \
    --jwk-json-path=jwks.json \
    --attribute-mapping="google.subject=assertion.sub,attribute.nucleus_upstream=assertion.nucleus_upstream,attribute.nucleus_tenant=assertion.nucleus_tenant,attribute.nucleus_att_tier=assertion.nucleus_att_tier,attribute.nucleus_att_epoch=assertion.nucleus_att_epoch,attribute.nucleus_evidence_digest=assertion.nucleus_evidence_digest" \
    --attribute-condition="assertion.nucleus_upstream == 'model-api' && assertion.nucleus_att_tier == 'attested' && int(assertion.exp) - int(assertion.nucleus_att_time) <= 900 && int(assertion.nucleus_att_time) <= int(assertion.iat) + 60"
```

- `--jwk-json-path` registers the JWKS inline (the issuer need not resolve); drop it to use
  discovery at `--issuer-uri`. After a key rotation, update it with
  `gcloud iam workload-identity-pools providers update-oidc … --jwk-json-path=…`, after
  re-running the `verify-node-evidence` check above on the new keys.
- `900` is the relying party's choice of the oldest quote it accepts at the assertion's
  `exp`. The node's own bound is `epoch + 30 + (exp − iat)`, 630 s with the defaults, so 900
  leaves room for one late re-quote. Lower it to tighten; below 630 some honest assertions
  are refused.
- The provider refuses a token when the condition is not exactly true, including when it
  cannot be evaluated, so an omitted claim refuses.
- The mapped `attribute.nucleus_att_tier` can gate a second time in the IAM binding:
  `--member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/attribute.nucleus_att_tier/attested"`.
- The access token the provider issues has its own lifetime (an hour by default). The
  freshness bound holds at the exchange; the node re-exchanges per its cache rule (ADR 0010
  §5), presenting a fresh assertion with the tier as of that mint.

A provider that does not evaluate CEL can still match `nucleus_att_tier = attested` as an
exact-string claim rule; it then has no age bound beyond the node's own 630 s.

## 3. Rotate the signing key

```text
  stage            wait ≥ overlap          promote          wait ≥ retire window        retire
  JWKS +next  ───────────────────────►  next → current  ───────────────────────────►  JWKS −prev
```

**Overlap** (stage → promote) = provider JWKS cache lifetime + longest assertion lifetime.
Default 15 min + 60 min = **75 min**. A provider that fetched the JWKS just before the stage
keeps that copy for its cache lifetime; the assertion-lifetime term is the profile's stated
margin (§1).

**Retire window** (promote → retire) = longest assertion lifetime + provider clock skew.
Default 60 min + 5 min = **65 min**. The old key may have signed an assertion just before the
promote; it stays acceptable until its `exp` plus the provider's skew allowance.

Change the terms with `--jwks-cache-ttl-secs` and `--max-assertion-ttl-secs`. Pass
`--upstreams` with them: the CLI then refuses a maximum below the registry's largest
`assertion_ttl_secs`. Both waits are enforced. A step taken early is refused and says when it
becomes allowed.

```bash
# 1. Stage. Prints the JWKS diff (+ new kid) and the new JWKS.
nucleus federation rotate --state-dir /var/lib/nucleus-node --stage
#    Static hosting: re-run `issuer --export` and upload now.
#    Inline:         replace the registered JWKS with the printed one now.
#    The overlap counts from the stage. If publishing takes a while, wait that much longer.

# 2. After the overlap. The published set does not change (the same two keys, relabelled),
#    so there is nothing to re-register.
nucleus federation rotate --state-dir /var/lib/nucleus-node --promote

# 3. After the retire window. Prints the JWKS diff (− old kid).
nucleus federation rotate --state-dir /var/lib/nucleus-node --retire
#    Static hosting: re-export and upload. Inline: re-register the printed JWKS.

# Any time: the keys, their stamps, and when the next step is allowed.
nucleus federation rotate --state-dir /var/lib/nucleus-node --status
```

**No restart.** The running node reads and validates the current key file for every assertion,
even if its inode, size and modification time have not changed. It never reads the staged key.
Each assertion retains one fixed signer for both its `kid` and signature. If the file fails its
checks (permissions, owner, parse), the node fails that exchange instead of carrying on with the
old key, and the pod's call returns "upstream call failed".

Only one rotation runs at a time: `--promote` is refused while a previous key is still
published. Retire it first.

**Interrupted steps** resume safely. A key file with no matching stamp in the rotation record is
stamped when the next step runs, so its wait starts again. A crash only makes a rotation slower,
never earlier. A leftover `jwt_svid_p256_rotation.lock` means a step is running or one crashed.
If none is running, remove it.

**Several nodes, one issuer.** Every node's keys must be in the one published JWKS. Each node
rotates on its own, and the published set is the union of every node's `--jwks`. Otherwise,
run one issuer per node.

## 4. What failure looks like

A provider does not say why it refused an assertion (profile §2.4). You see a coarse refusal
at the token endpoint, typically `400 invalid_grant` or `401`. The pod sees
"upstream call failed" and the node logs the exchange's `jti` and status. The usual causes, in
order:

| symptom | cause | fix |
|---|---|---|
| every exchange refused right after a promote | the provider has not seen the new `kid`: the JWKS was not published before the overlap ran, or the provider caches longer than `--jwks-cache-ttl-secs` | re-publish; the provider SHOULD re-fetch on an unknown `kid` (§2.2 item 9), but an inline registration never will |
| every exchange refused right after a retire | a provider still holds an assertion signed by the old key, or the retire window was shortened below the registry's `assertion_ttl_secs` | re-publish the old key's JWKS (keep `--jwks` output from before the retire) |
| every exchange refused from the start | `iss` differs from the discovery `issuer` (trailing slash, scheme, path), or the rule's `aud` is not the registry audience | compare `--export` output and `--claims-for` with the provider's registration |
| node will not start: "mode … must be readable by its owner only" | the key file's permissions were widened | `chmod 0400` so the node can start, then assume the key was read: rotate it |
| rotation refused: "owned by uid …" | the CLI ran as a different user than the node | run it as the node's user |
| key creation, signing or rotation refused: directory permissions | the state directory is writable by a group or other users | restrict writes to the node's owner before retrying |
| node will not start: "holds file federation keys but this node is configured for TPM-resident custody" | the node gained `--node-evidence-tpm` over a file key | pass `--allow-federation-key-in-file`, or move the file key aside and publish the new TPM key's JWKS |
| log: "TPM-resident key … is bound to another boot state; regenerating" | the node booted a different kernel, initrd or command line | publish the new JWKS (`issuer --export`); the old key cannot sign in this boot |
| `rotate --stage` refused: "holds TPM-resident federation keys" | `--tpm` was not given | pass `--tpm /dev/tpmrm0` |
| node will not start: "… This node seals its keys to the TPM and does not fall back to a key file" | the TPM could not be reached, or refused to seal an Ed25519 node key | fix the TPM; the key file is untouched. `--allow-node-keys-in-file` keeps the keys as files |
| node will not start: "… holds the key sealed to a TPM … The custody is never crossed" | `--node-evidence-tpm` was removed, or `--allow-node-keys-in-file` added, over sealed node keys | restore the TPM flag without the waiver |
| node will not start: "… holds a DIFFERENT key from the sealed one" | a `.der` file was put back beside a sealed key | move one of them aside; the node will not pick an identity |
| log: "… cannot be unsealed: it is sealed to another boot state … A NEW key replaces it" | the node booted a different kernel, initrd, boot loader or command line | expected after an upgrade; tell anything that pinned the old node key. Booting back and restoring `….unusable-<time>` recovers the old key |
