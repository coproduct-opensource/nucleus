# Workload namespace: wire types and verifier binding first — 2026-11-13

#3528 (closed unmerged) carried two halves: the wire types and receipt binding for a workload's
namespace placement, and the Linux user+network namespace setup that would make a private
placement true. Its runtime half conflicts with main's PID namespace (#3344) in `hardening.rs`
in a way that decides what a signed receipt claims, so it is deferred. This change lands only the
first half, and makes the runtime refuse what it cannot yet enforce.

## What a receipt now says

`ExecutionClaim` gains `namespace: NamespaceSetup` and the node signs `nucleus.execution.v2`.
The setup is read off an `AdmittedNamespace`, which only `WorkloadNamespace::admit` mints, and
this runtime admits only `runtime` placement. So every v2 receipt this runtime signs says
`runtime`.

`verify_execution` decides the binding in one function, `namespace_binding`, after
authentication and after the sandbox tier check (a shared-UID run is refused as that, whatever
its schema):

| signed schema | signed namespace | expected namespace | result |
|---|---|---|---|
| v2 | X (recorded) | X (recorded) | verifies |
| v2 | X | Y ≠ X | `Binding("namespace")` |
| v2 | absent / `unrecorded` | anything | `Binding("namespace")` |
| v2 | anything | `unrecorded` (no expectation stated) | `Binding("namespace")` |
| v1 | absent | `unrecorded` | verifies; the claim reports `unrecorded` |
| v1 | absent | any recorded value, `runtime` included | `Binding("schema")` |
| v1 | a recorded value | `unrecorded` | `Binding("namespace")` |

The namespace is inside the signature: editing it in a signed body fails authentication
(`a_tampered_namespace_fails_authentication`).

## What admission refuses

`spec_posture::admit` (the node's create-time decider) refuses a spec whose
`workload.namespace` is anything but `runtime`, naming the field. The tool-proxy's launch
admission calls the same decider, so a spec that reaches it another way is refused there too, and
`completed_claim` and the admission record use it again before anything is signed or published.
A spec that omits `namespace` serializes exactly as before.

**Consequence for consumers.** A consumer that sends `private_user_network` is refused at create
until the runtime half lands. That is the intent: it was otherwise going to run in the runtime's
namespaces.

## The corrected assumption

#3528 refused every v1 receipt (`Binding("schema")`), on the reasoning that a body with no
namespace cannot attest runtime placement. On main that breaks a test #3528 never saw:
`attested_journey_cli`'s fixture is a v1 receipt from a live node, re-verified from a stored
expectation with no namespace. Refusing v1 outright would have made every already-issued v1
receipt unverifiable by anyone holding it. The reasoning still holds for any expectation that
names a namespace, so v1 is refused there, and accepted only where nothing about namespace is
asked and nothing is claimed.

## Deferred

`nucleus::hardening::workload_namespace`, the `Isolation`/`Posture` changes, the launch-receipt
preimage gaining `namespace=`, and the tool-proxy wiring that would admit `private_user_network`.
Admitting it is a change to `WorkloadNamespace::admit`'s one arm, and the tests here say what
moves when it does.

## Validation

Drove each new check red first (A-19), on macOS:

- `admit` returning `runtime` for a private request: the spec and tool-proxy admission tests
  failed.
- `namespace_binding` skipping the v2 equality: two verifier tests failed.
- `namespace_binding` accepting v1 against a recorded expectation: two verifier tests failed.
- The namespace binding moved ahead of the tier check: the tier-order test failed.

## 2026-11-14: the runtime half

The deferred half is `docs/findings/workload-user-network-namespace.md`. It changes two
statements above. `WorkloadNamespace::admit` now admits `private_user_network` where the
deciding site's runtime makes it (a Firecracker guest whose workload has its own PID namespace,
on a kernel with user namespaces), with `workload.uid` stated. And the claim's `namespace` is
read off the hook's record, which the node signs only if it equals the admitted setup. "Every v2
receipt this runtime signs says `runtime`" was true at #3534 and is not after the runtime half.
