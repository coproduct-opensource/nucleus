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

To start watching before a workload requests approval:

```sh
nucleus node effect-approvals <pod-uuid> list --wait-secs 120
```

This polls once per second and returns JSON containing the unexpired pending
entries as soon as any are available. Without `--wait-secs`, list remains an
immediate snapshot of all returned statuses. The wait is bounded (1–86400
seconds), including time spent in HTTP requests; a timeout exits unsuccessfully.
Server and authentication errors stop the wait. Waiting never grants or refuses
an effect and never cancels the pod. It does not extend the workload's own
approval-wait timeout. Review the returned effect before granting it.

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

## Approvals that declassify tainted data

Each listed approval has a `category`. Most are `"ordinary"`. A push or pull
request from a session that has received untrusted content (an upstream or model
response, for example) is held rather than refused. Its approval is listed as
`{"declassification": {"input": {...}}}`. Granting it releases that session's
data into the sink, which is the declassification. `input` is the host's label
for the data when it held the request (integrity, confidentiality, derivation).
The signed authorization record of the released effect carries the same label.

Review of a declassifying approval adds a `declassification` block with:

- a notice;
- the labels in words, for example `adversarial: content an outside party controls`;
- the sink (operation and destination);
- the bound request: method, URL, query parameter names, forwarded header names,
  and body SHA-256 and size.

The full payload is in `body_base64`, and in `body_utf8` when it is valid UTF-8,
as for every review. An ordinary approval's review has no such block.

A grant releases only what the operator was shown. Suppose a request was granted
as ordinary and the session became tainted before the request ran. The grant does
not release it: the host refuses the stale approval and lists a fresh
declassifying one. There is no bulk grant. Each `grant` settles exactly one
approval by its ID and effect hash.

## Granting and refusing

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
