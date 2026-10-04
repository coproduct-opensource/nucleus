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
For a workload request paused at the host, a grant resumes that same staged
request after fresh policy checks. It consumes the approval once. For an
immediately refused or timed-out request, the workload must retry with the same
payload and a fresh stream nonce. A changed payload or operator charge needs a
new approval. Pending approvals expire after five minutes.

To refuse a request:

```sh
nucleus node effect-approvals <pod-uuid> refuse <approval-uuid>
```

These commands require HTTPS with the operator's mTLS identity. HMAC secrets
cannot substitute for it. Node mTLS management requests do not follow redirects.
A server refusal or stale approval exits unsuccessfully; refresh the list before
retrying. After reviewing the request, use its effect hash for the explicit grant
command.

## Workload pause and resume

Local capability and information-flow denials stop a request at the proxy.
A local approval deferral is instead carried in the signed broker request as
`require_approval`; it never becomes a guest execution grant. The host requires
operator review when either that flag or its own policy requires approval.
The flag is part of the canonical effect digest and appears in request review
when set. A guest-side approval cannot substitute for host review.

Streamed workload requests pause at the host for up to 120 seconds when approval
is required. The complete upload
has already been staged, so approving resumes the original request without
re-uploading it or spending a second guest-side authority. The host does not mint
credentials or call the upstream while waiting. It rechecks policy, taint,
revocation, budget, and approval validity before dispatch.

Workloads can set `x-nucleus-approval-wait-seconds` to an integer from 0 to 120;
0 requests immediate refusal. Other values are rejected. The workload client's
own timeout must allow the chosen pause plus upstream processing. Operator
refusal, wait timeout, pod revocation, or broker disconnect does not dispatch
the pending request. A timeout leaves its review available until approval expiry.

The stream protocol makes waiting explicit; an omitted or zero
`approval_wait_seconds` keeps legacy immediate-refusal behavior. The host caps
larger protocol values at 120 seconds. Opted-in broker clients keep their upload
half open after END while waiting; EOF is treated as cancellation. Updated proxies that request a pause
require an updated host; older hosts reject the unknown field. Buffered PERFORM
calls retain their existing explicit retry behavior. This pause does not bypass
the proxy's local permission or information-flow gates.
