# nucleus-cb4a-lint — the `cb4a_separation` pass

Mechanises the two normative MUSTs of the IETF draft **Credential Broker for
Agents** ([`draft-hartman-credential-broker-4-agents-00`](https://datatracker.ietf.org/doc/draft-hartman-credential-broker-4-agents/)):

> The component that decides "yes" (**PDP**) MUST never touch credential
> material. The component that dispenses credentials (**CDP**) MUST never make
> policy decisions.

The draft states these as prose about components. This pass states them as
**reachability over the call graph**: nothing reachable from a PDP root may name
credential material, nothing reachable from a CDP root may name a policy type.

## Why a lint, when the signatures already say it

`pdp_decide` takes no `CredentialStore` and `cdp_fetch` takes no
`PermissionLattice`, which closes the *direct* case at the type level. But a
signature says nothing about what a function does two hops down — and that is the
shape separation-of-duty failures actually take. Nobody adds `CredentialStore` to
the decider's arguments; they add it to something the decider calls.

That case is not hypothetical here. Perturbing the real `nucleus-node` so that
`pdp_decide` calls `perturbation_hop` → `perturbation_audit_helper`, and only the
last of those constructs a `CredentialStore`, the pass reports:

```
warning: `broker::perturbation_audit_helper` is reachable from a PDP entry point
         and names `nucleus_cred_broker::CredentialStore` (matches `Credential`)
  --> crates/nucleus-node/src/broker.rs:91:1
   = help: CB4A: the component that decides MUST never touch credential material.
```

Every signature in that chain is clean. Only the closure sees it.

## Forward, not backward

The sibling `nucleus-mediation-lint` closes **backward** — from I/O primitives up
to public entry points, asking "can anything reach an effect without a token".
This one closes **forward** from named roots, asking "can *this designated
function* reach a forbidden thing". Same fixpoint machinery, opposite direction.

That difference has a real consequence. A backward closure that stops at a crate
boundary still catches the defect, because the callee's own crate gets its own
pass. A **forward** closure that stops at a crate boundary genuinely stops.

## The other half of the argument

Because the forward closure stops at the crate boundary, this pass is only half
of FM-2. The other half is in `deny.toml`, which lists `nucleus-cred-broker` with
`wrappers = ["nucleus-node"]`, so **only the composition root may link credential
material at all**. Inside that crate this lint applies; outside it, the ban does.

Neither half is sufficient alone, which is why both exist:

- the ban cannot see *inside* `nucleus-node`, where both halves legitimately link;
- the lint cannot see *outside* the crate it is scanning.

## Running it

```sh
cargo build --manifest-path tools/nucleus-cb4a-lint/Cargo.toml

DYLINT_LIBRARY_PATH=$PWD/tools/nucleus-cb4a-lint/target/debug \
  cargo dylint --lib nucleus_cb4a_lint -- -p nucleus-node
```

Dylint resolves the library by a `@<toolchain>-<target>` suffixed filename. If
`cargo dylint` reports `Could not find --lib nucleus_cb4a_lint`, copy the built
dylib to that name:

```sh
cd tools/nucleus-cb4a-lint/target/debug
cp libnucleus_cb4a_lint.dylib \
   "libnucleus_cb4a_lint@nightly-2026-04-16-$(rustc -vV | sed -n 's/host: //p').dylib"
```

## Current status

Clean on `nucleus-node`, `nucleus-cred-broker`, `nucleus-tool-proxy` and
`portcullis-effects`.

**A clean pass means nothing until it is shown to fire**, and a silent pass here
has a second failure mode beyond the usual one: if no root matched, the closure
never runs and the result is indistinguishable from "no violations". So the clean
result above rests on three perturbations, each of which produced a report:

| Perturbation | Crate | Result |
|---|---|---|
| `pdp_decide` → helper → helper that builds a `CredentialStore` | `nucleus-node` | flagged, at the two-hop helper |
| `cdp_fetch` → helper that reads a `PermissionLattice` | `nucleus-node` | flagged |
| `for_request` → helper naming a policy type | `nucleus-cred-broker` | flagged |

The first two also establish that `pdp_decide` and `cdp_fetch` are actually
matched as roots; the third does the same for `for_request` in a different crate.

## What a clean pass does NOT establish

- **Anything past a crate boundary** — see "The other half of the argument".
- **That the roots are the real PDP and CDP.** `PDP_ROOTS` and `CDP_ROOTS` match
  by name. Renaming `pdp_decide` without updating the list removes the check
  *silently*, which is the one way a root list is worse than no root list.
- **Anything about data flow.** "Does not name" is syntactic. A credential
  laundered through an opaque `&[u8]` across three layers of generics would pass.
  Closing that is FM-1's job, not a lint's.

## Known limitation: UI tests do not run on macOS

Identical to the sibling passes: the dylib resolves `rustc_driver` through
`@rpath`, which `DYLD_FALLBACK_LIBRARY_PATH` does not satisfy, and SIP strips
`DYLD_*` from the child processes the test harness spawns. There is therefore no
committed `ui/main.stderr` — generating one requires running the harness, and a
hand-written baseline would be fabricated. The fixtures in `ui/main.rs` are
exercised via `cargo dylint` directly, as above.
