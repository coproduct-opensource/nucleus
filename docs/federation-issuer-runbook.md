# Federation issuer — operator runbook

A node with `--federation-issuer` signs short ES256 assertions that its pods' upstream
credentials are exchanged for (ADR 0010; the wire contract is
`docs/federated-upstream-profile.md`). A provider accepts them only if it knows this issuer's
keys and has a rule saying which assertions map to which of its principals. This runbook covers:

1. publishing the issuer (static hosting, or an inline JWKS);
2. the provider rule to register;
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

**No restart.** The running node checks the current key file on every assertion and reloads it
when a promote has replaced it. It never reads the staged key. If the replaced file fails its
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
