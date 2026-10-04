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
including its payload and operator charge. To inspect the exact payload retained
by the host:

```sh
nucleus node effect-approvals <pod-uuid> review <approval-uuid>
```

Review returns the resolved request metadata and complete payload in base64,
plus JSON-escaped text when it is valid UTF-8. The CLI recomputes the payload
hash, checks its length, and recomputes the canonical effect digest before
printing. A substituted body, destination, charge, or approval fails review.
Injected credential values are excluded; the header name remains visible.

Only approval-gated requests retain review payloads, up to 64 MiB per pod across
all retained approvals. Expired reviews are inaccessible and pruned on subsequent
approval access. A request that cannot be retained
for review is refused. Review data is held in memory and is separate from the
durable authorization and outcome journals. The request describes what will be
sent; understanding the remote API's semantics remains part of operator review.

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
retrying. Automatic harness pause/resume remains release work. After reviewing the
request, use its effect hash for the explicit grant command.
