# nucleus-envelope-adversarial-corpus

Hand-crafted bad bundles that every [`nucleus-envelope`](../nucleus-envelope)
verifier **must reject** — the CI-gated security promise.

[![docs.rs](https://img.shields.io/docsrs/nucleus-envelope-adversarial-corpus)](https://docs.rs/nucleus-envelope-adversarial-corpus)

Every entry returned by `corpus()` is a bundle constructed to exercise a specific
failure mode. For each case, `verify_bundle(&case.build(), &case.anchor())` MUST
return an error — when one doesn't, a regression has slipped past the per-edge
proof / hash-chain / Merkle / trust-anchor checks.

This is wired into CI as a **load-bearing gate**: `cargo test -p
nucleus-envelope-adversarial-corpus` on every PR is what turns "we ran an audit"
into "an adversary's attacks fail every merge." The crate is a *library* (not
just tests) so external auditors can run it against our cases and the threat-model
doc can cite it by name.

## What's covered

The cases (C01, C02, …) are drawn from the standard CT-log / X.509 transparency
attack catalogue plus the OIDC OP audit's HIGH findings — e.g. tampered edges,
swapped signatures, truncated/empty envelopes, attacker-supplied JWKS, unknown
`kid`, foreign parents, and non-pod session roots. Each `AdversarialCase`
carries:

- `name` — stable identifier for audit reports + test failures
- `summary` — the attack it exercises
- `expected_kind_substr` — a `Debug` substring of the `VerifyBundleError` variant
  expected, so the corpus survives error-message rewording while still pinning
  the failing variant

## Adding a case

1. Write a builder fn returning a `Bundle` (start from
   `fixture::known_good_bundle`, mutate, return).
2. Add an `AdversarialCase` to `corpus()` with name + summary + `expected_kind`.
3. Document the attack scenario in the doc-comment above the builder.

## Referenced by

- `docs/verifier-service-threat-model.md`
- `docs/audit-charter.md`

## License

MIT
