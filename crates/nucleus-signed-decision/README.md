# nucleus-signed-decision

An owner decision an agent can verify: "of these options for this question, the owner chose
this one", signed, scoped and time-bounded. Without a format, a decision reaches an agent as
text (an issue comment, a brief, a memory file), and any text can claim to be one. This crate
is the format and the only verifier.

## The records

| record | bytes | role |
|---|---|---|
| `OptionBody` | `nucleus/owner-option/v1\n` + JSON | one option as shown; its SHA-256 is `option_sha256` |
| `QuestionCore` | `nucleus/owner-question/v1\n` + JSON | the frozen question, options and recommendation; `question_sha256` |
| `OwnerDecision` | `nucleus/owner-decision/v1\n` + JSON | one decision; its SHA-256 is the `DecisionId` |
| `DecisionBatch` | `nucleus/owner-decision-batch/v1\n` + JSON | what the owner's key signs: kid, aud, nonce, 1 to 25 decisions |

JSON is `serde_json` of the struct in declared field order, which is the `gate approve`
convention. It is not RFC 8785. The verifier checks the signature over the received bytes,
parses them with `deny_unknown_fields`, re-serializes them, and refuses unless the two byte
strings are equal. That refuses reordered fields, duplicate keys, whitespace, alternative
escapes and omitted optional fields, with no second canonicalizer to drift.

## Verifying

```rust,ignore
let roots = TrustRoots::from_json(&std::fs::read_to_string(roots_path)?)?; // operator config
let bundle = DecisionBundle::from_slice(&bytes)?;                          // untrusted bytes
let decision: SignedDecision = verify(&bundle, &roots, now, tenant)?;
```

`verify` is the only constructor of `SignedDecision`. It refuses, by name: a signature that no
pinned key made (`BadSignature`, or `UnknownKid` when the batch names an unpinned kid),
non-canonical bytes, a wrong tenant, a bundled question whose option digests (`OptionsMismatch`)
or question digest (`QuestionMismatch`) differ from what the owner signed, a `chosen` that is
not exactly one listed option, a scope wider than proposed, and a window that is malformed,
not yet open, or closed.

Trust roots use the control plane's approvers shape, `[{kid, public_key, who}]` with an SPKI
PEM key. P-256 (the owner's Secure Enclave key, X9.62 DER signatures) and Ed25519 (64-byte
signatures, `verify_strict`) are accepted, and the algorithm is read from the SPKI. The kid is
derived from the key (the first 16 hex of SHA-256 over the trimmed PEM), and a file whose kid
disagrees with its key is refused.

## Using

- `covers(ScopeRef)` and `covers_action(&Action)` return `Covered`, `OutOfScope` or `CannotTell`.
  Refs and capabilities match exactly. A path matches an identical path, a `<dir>/**` it is
  strictly under, or `**`. Any other glob in a signed pattern is `CannotTell`, never covered,
  and so is an action whose write set is unknown.
- `DecisionLedger` holds verified decisions in one process. A standing decision is `cite`d and
  re-checked for window and scope on every use. A one-shot decision is `spend`t or `consume`d by
  value, once. A copy re-verified from the same bytes has the same id and is refused as `Spent`.
  A decision that `supersedes` another retires it.

## What it does not claim

- Single use is per process. Fleet-wide single use is the merge gate's job.
- Supersession covers what the ledger has seen. Offline, the window is the bound.
- Log inclusion proofs are not checked yet. This crate checks the owner's signature.

The golden test checks every digest in the control plane's published pending batch
(`testdata/pending-2026-10-13.json`), so this encoding is pinned to the one that produced them.
