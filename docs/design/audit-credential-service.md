# Scoped audit credential service

Configure the node with `--audit-minter-socket /run/nucleus/audit-mint.sock`
alongside `--audit-sinks`. The socket belongs to an operator-provided host service;
provider-specific policy construction and token issuance remain outside Nucleus.
Without a configured minter, pods requesting an audit sink are refused.

Each mint uses a fresh Unix connection and one newline-terminated JSON request:

```json
{"schema":"nucleus.audit-mint.v1","scope":{"endpoint":null,"region":null,"bucket":"operator-audit","prefix":"nucleus/team-a"},"ttl_seconds":900}
```

The scope comes from admission's resolved sink and narrowed prefix. The service
must issue a new temporary credential restricted to object writes beneath that
exact prefix at that endpoint and bucket. It must not grant reads, listing,
deletion, other destinations, or return its own minting identity. A null prefix
means the admitted sink covers the whole bucket. A null endpoint or region uses
the object-store client's default, which the operator service must agree on.

Successful response, terminated by a newline:

```json
{"status":"granted","access_key_id":"temporary-id","secret_access_key":"temporary-secret","session_token":"temporary-token","expires_at_unix":1791166500}
```

`session_token` may be null or omitted. `expires_at_unix` is an unsigned integer
number of seconds since the Unix epoch. The timestamp above is illustrative;
the service must return a currently valid credential within the requested TTL.
The node validates nonempty keys, expiry, and the requested lifetime using the
same admission path as other minters. Refusal is `{"status":"refused"}` followed
by a newline. Unknown fields and malformed responses are refused. Replies are
limited to 16 KiB; connection, request, and reply share a ten-second deadline.
Failure never falls back to ambient credentials. Response bytes and parser
diagnostics are not included in returned errors.

The service is trusted to enforce the credential's actual object-store policy;
JSON fields cannot prove those restrictions. Keep the socket and its directory
host-owned and unavailable to workloads. The node sends no ambient cloud key to
this socket, and the socket is never passed to a pod. The operator service owns
its provider authentication. Test real provider enforcement separately before
claiming the scoped-credential release requirement is complete.

Credentials are minted once per pod. Refresh after credential expiry is not yet
implemented; the existing maximum lifetime remains twelve hours. This interface
does not turn the development local driver into an isolation boundary.
