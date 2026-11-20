# Request-proof consumption order — 2026-10-11

A real TLS exchange test reproduced an availability defect: presenting a copied
issuer assertion without its DPoP proof returned 401 but consumed the issuer
validator's replay slot. The legitimate sender's later proof-bound exchange then
also returned 401. The prior adapter tests used fresh assertions per negative
case and did not exercise that sequence.

`ExternalIssuerValidator::check` now returns a non-cloneable `PendingCaller`
holding signature/claim evidence and a reference to its exact validator. It grants
no caller authority. The node checks the issuer's key binding, CSR and DPoP before
consuming replay. `PendingCaller::consume` takes the witness by value (ADR 0007
C-4), rechecks expiry and atomically consumes the existing replay cache. The
convenience `validate` API still checks and consumes in one call, preserving its
existing contract. The durable request-proof/assertion store remains the restart
boundary in DPoP mode; this does not replace it with the in-memory issuer cache.

The original failing test is now green: a missing-proof attempt does not spend
the assertion, a legitimate TLS exchange succeeds, and a fresh proof cannot
resurrect that spent assertion. The returned SVID is used for a real mTLS API
request with a delegation-bound proof; replay is rejected.

Validation:

- Four node request-proof tests, including two real TLS/mTLS tests, passed.
- All 15 node federation tests passed (includes two of the four above).
- All 28 issuer-validator integration tests and 23 federation library tests passed.
- Federation library Clippy with `-D warnings` completed successfully; existing
  configuration warnings about unreachable disallowed paths remain.

Tests use ephemeral identities and loopback listeners. The API probe runs the
production proof adapter but does not establish pod authorization or workload
confinement. The exchange test runs the actual issuer/CA fixture and TLS listener;
it is not evidence that any deployed gateway or node was updated. No live node,
credentials or application data changed. The initial sandbox run was unable to
bind loopback; the same compiled tests passed with local socket permission.
