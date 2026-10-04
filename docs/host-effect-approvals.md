# Approving host-mediated effects

The node operator can review, grant, or refuse pending broker effects from the
CLI. Use the client identity whose SPIFFE ID matches the node's configured root
minter. A workload identity cannot approve its own effects. `nucleus setup`
provisions the default CLI identity; explicit identities use `--tls-cert`,
`--tls-key`, and `--trust-bundle` before the subcommand.

List the host's review metadata:

```sh
nucleus node --url https://127.0.0.1:8080 effect-approvals <pod-uuid> list
```

The JSON includes each approval's ID, operation, resolved destination, effect
SHA-256, fixed operator charge in micro-USD, expiry, and status. Strings are
JSON-escaped for safe terminal display. The hash binds the resolved request,
including its payload and operator charge, but **the payload itself is not
shown**. Review the intended request through an independently trusted source;
a digest alone does not explain what a remote API will do.

Grant the exact effect you reviewed:

```sh
nucleus node effect-approvals <pod-uuid> grant <approval-uuid> \
  --effect-sha256 <64-hex-character-effect-hash>
```

The CLI fetches current metadata and refuses a missing, expired, already-decided,
ambiguous, or mismatched approval before posting a grant. The host remains the
final authority: it rechecks status and expiry when settling, then rechecks
policy, taint, revocation, and budget when the workload retries its effect.
A successful grant does not dispatch the request by itself. The matching retry
consumes the approval once; a changed payload or operator charge needs a new
approval. Pending approvals expire after five minutes.

To refuse a request:

```sh
nucleus node effect-approvals <pod-uuid> refuse <approval-uuid>
```

These commands require HTTPS with the operator's mTLS identity. HMAC secrets
cannot substitute for it. Node mTLS management requests do not follow redirects.
A server refusal or stale approval exits unsuccessfully; refresh the list before
retrying. Complete payload review and automatic harness pause/resume remain
release work; these commands expose the existing host approval mechanism.
