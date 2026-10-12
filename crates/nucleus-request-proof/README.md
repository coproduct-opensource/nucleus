# Native request-proof verification

MIT-licensed runtime component; no private control-plane dependency. It reuses
`nucleus-identity` ES256 verification and the same P-256 SPKI decoder for peer
certificates and CSRs. Native Olog stores replay claims durably before authority
is returned. The directory requires one exclusive writer and owner-only access.

The HTTP node integration is enabled by configuring both:

```
--request-proof-api-origin https://node.example:8080
--request-proof-exchange-origin https://node.example:8444
```

Origins must describe the exact client-visible HTTPS origin, without a path,
query, fragment or URL credentials. Neither Host nor forwarding headers supplies
trust. Enabling only one origin is an error. gRPC cannot be enabled in this mode
until it has an equivalent metadata proof adapter. Omitting both flags retains
the public runtime's prior mTLS/Bearer federation mode; deployments requiring
DPoP must explicitly configure both, and must not rely on that legacy mode.

Federation requires `Authorization: DPoP <JWT>` with issuer-signed `cnf.jkt`, a
CSR for the same key, and a fresh proof binding the JWT. After issuer validation,
CSR and proof verification, the node retires both proof and assertion in one
native commit, then issues the SVID/delegation and returns `cnf.jkt`. Assertion
replay keys hash the signed JWT content, excluding its potentially malleable
signature. Fresh proofs do not resurrect spent assertions after a restart.

HTTP API proofs must use the TLS-verified certificate's P-256 key. Where a
`x-nucleus-delegation-cert` is presented, its exact bytes are bound by `ath`;
otherwise `ath` must be absent. The existing SPIFFE route authorization still
runs. Missing/duplicate proofs, wrong keys, method/target/token mismatches,
private/unknown JWK members, unexpected claims, expired/future proofs and replay
are refused. This adapter does not use a nonce; unexpected nonce claims fail.

Proof lifetime is 60 seconds with at most 5 seconds future skew. One mutex
serializes replay decisions and commits. A failed commit poisons the handle.
Expired rows are removed in the admitting transaction; live rows are never
removed to make capacity. At 4096 live proof/assertion rows admission returns
unavailable, not success. Cleanup scans are bounded by that cap. This is not a
throughput or formal verification claim. DPoP does not bind request bodies or
query strings; authenticated TLS and application authorization remain required.

Verification in the staging workspace: five crate tests (including concurrent
and restart replay), two node HTTP adapter tests, 14 federation regression tests,
and 11 existing SPKI/JWS tests passed. Default and local-driver node test builds
compile on macOS. Actual TLS deployment and client/node cutover remain separate
acceptance requirements.
