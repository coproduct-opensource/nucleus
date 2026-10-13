# Migrating did:web identifiers (#3377)

#3377 changed how a SPIFFE identity maps to a `did:web` identifier. Any
`did:web` string produced by `Identity::to_did_web` before that change is now
refused by `Identity::from_did_web`. Stored or published identifiers have to be
migrated explicitly; nothing translates them for you.

## What changed

| | Before #3377 | After #3377 |
|---|---|---|
| Shape | `did:web:<account>.<trust-domain>` | `did:web:<trust-domain>:ns:<namespace>:sa:<account-segments>` |
| Example | `did:web:music-app.groundtruth.dev` | `did:web:groundtruth.dev:ns:apps:sa:music-app` |
| DID document location | `https://music-app.groundtruth.dev/.well-known/did.json` | `https://groundtruth.dev/ns/apps/sa/music-app/did.json` |
| Namespace | dropped | kept, and must equal the caller's expected namespace |
| Multi-segment account (`sa/owner/repo`) | did not round-trip | `sa:owner:repo` |

The old shape was ambiguous:

- Two workloads with the same account name in different namespaces got the same DID.
- An account containing dots read as a subdomain, so it could parse as a different trust domain.

The new shape uses the did:web method's colon-delimited path syntax
([method-specific identifier](https://w3c-ccg.github.io/did-method-web/#method-specific-identifier)),
so the whole SPIFFE ID is carried, and a DID parses back to exactly one identity.

Method signatures did not change. `from_did_web(did, expected_namespace)` still takes the
namespace, and now refuses a DID whose `ns:` segment differs from it.

## What is refused

`from_did_web` returns `InvalidSpiffeUri` for:

- the old subdomain shape (`did:web:worker.example.com`);
- any non-canonical alias: an empty segment, `..`, an empty account, or `::`;
- a namespace other than the expected one.

The parse goes through the canonical SPIFFE parser, so a DID that parses is
also a valid SPIFFE ID (ADR 0007 G-1). Parsing is not proof that the caller
controls the DID; that still requires resolving and checking the DID document.

## Migrating

1. **Find stored identifiers.** Search configuration, databases, A2A agent
   cards (`params.did` in the [runtime-guarantees extension](a2a-runtime-guarantees-extension.md)),
   and DID-binding records (`SpiffeDidBinding.did`, `BindingProof.did_key_id`) for `did:web:`
   values that came from a SPIFFE identity.
2. **Recompute, don't rewrite by hand.** The old shape lost the namespace, so
   it can't be converted mechanically. Start from the workload's SPIFFE ID and
   call `Identity::to_did_web`. If all you have is the old DID, you have to look
   up which namespace the account lived in.
3. **Move the DID document.** It is now served under the trust domain's path:
   `https://<trust-domain>/ns/<namespace>/sa/<account>/did.json`. The
   per-account subdomain is no longer used. If old relying parties still
   resolve the old location, serve both until they have moved, then remove the
   old one.
4. **Re-sign anything that names the DID.** Verification-method ids
   (`<did>#<key>`) and DID-binding records contain the DID string, so signatures
   over them have to be re-issued under the new identifier.

`did:web` identifiers that never came from a SPIFFE identity (any
`did:web:<domain>` you publish yourself) are unaffected. Only the SPIFFE
mapping changed.
