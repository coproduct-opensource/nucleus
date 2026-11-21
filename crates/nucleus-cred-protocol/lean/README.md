# `nucleus-cred-protocol` Lean extraction: the broker's egress decisions

`generated/NucleusCredProtocol/{Types,Funs}.lean` is the Charon → Aeneas
translation of `crates/nucleus-cred-protocol/src/extracted/`, unmodified. That
module is not a mirror of production code: the production functions below
convert their inputs and call it, so these definitions are of the code that
decides (ADR 0007 G-1).

| decision (`ci/egress-decisions.toml` id) | production fn | extracted def | parity test (old implementation vs. production) |
|---|---|---|---|
| `operation_for` | `nucleus_cred_protocol::egress::operation_for` | `extracted.classify.operation_for` | `crates/nucleus-cred-protocol/src/extracted/parity_tests.rs::operation_for_decides_as_before` |
| `effect_table_declared` | `EffectTable::declared` | `extracted.classify.declared` | same file, `declared_decides_as_before` |
| `effect_table_from_parts` | `EffectTable::from_parts` | `extracted.classify.from_parts` | same file, `from_parts_decides_as_before` |
| `credentialed_egress_admitted_by` | `CredentialedEgressSpec::admitted_by` | `extracted.admission.admitted_by` | `crates/nucleus-spec/src/egress_decisions_parity_tests.rs::admitted_by_decides_as_before` |
| `credentialed_egress_clamp` | `CredentialedEgressSpec::clamp` | `extracted.admission.clamp` | same file, `clamp_decides_as_before` |
| `admit_upstreams` | `PodAuthority::admit_upstreams` | `extracted.admission.admit_upstreams` | `crates/nucleus-node/src/pod_authority/tests/egress_parity.rs::admit_upstreams_decides_as_before` |
| `header_policy` | `nucleus-node` `upstreams::header_policy` | `extracted.headers.header_policy` | `crates/nucleus-node/src/upstreams_parity_tests.rs::header_policy_decides_as_before` |
| `forwarded_headers` | `nucleus-node` `broker_stream::forwarded_headers` | `extracted.headers.forwarded_headers` | `crates/nucleus-node/src/broker_stream/tests/forwarded_parity.rs::forwarded_headers_decide_as_before` |

The header-name rules the last two stand on (`workload_egress::guest_may_propose_header`,
`names_a_credential`, `header_value_admissible` in `nucleus-spec`) are shells
over `extracted.headers.*` too, held by `header_rules_decide_as_before`.

The parity tests compare the implementation each function had before the
rewrite, kept test-only, with the production function on generated inputs.
Each was driven red by mutating the extracted core (2026-11-18). They are
Rust-to-Rust: they show the rewrite changed no decision. No theorem is
stated over these definitions yet.

## What the extraction says about the code, and what it does not

* The admission functions are generic over the entry type, with its
  `PartialEq` and `Clone` as instance arguments. A statement over them
  quantifies over every equality; that the derived `PartialEq` of
  `CredentialedEgressSpec` compares every field, and that its derived
  `Clone` returns an equal value, are facts about the Rust type that a
  statement must assume, not facts this extraction contains.
* The production shells (string to bytes, map to list in iteration order,
  index to the refused entry's text) are not extracted. Each is a
  conversion with no decision in it, and the parity tests run through it.
* The extraction contains no axiom: Aeneas emitted no `FunsExternal`
  template. `Vec::is_empty` would have been one, which is why the source
  writes `len() == 0`.

## How it was produced

Pinned to what `.github/workflows/aeneas-*.yml` use: the prebuilt Aeneas
release `nightly-2026.06.10` (its bundled Charon reports `0.1.212`), Rust
`nightly-2026-06-01` for Charon, Lean `v4.30.0`, and the Aeneas Lean library
at `5138c03b` (the commit behind that release). The 2026-11-18 run used the
release's `aeneas-macos-aarch64.tar.gz`, whose SHA-256 was checked against
the release's published digest
(`eeeac99f622252b7d518456fcd0bf6e6b55d68c1a4b8e835ff874a7be3d34014`).

From `crates/nucleus-cred-protocol`, with the release's `charon` and
`aeneas` on `PATH`:

```text
cargo clean -p nucleus-cred-protocol        # charon emits nothing on a warm target
charon cargo --preset aeneas \
  --start-from nucleus_cred_protocol::extracted::classify::operation_for \
  --start-from nucleus_cred_protocol::extracted::classify::declared \
  --start-from nucleus_cred_protocol::extracted::classify::from_parts \
  --start-from nucleus_cred_protocol::extracted::admission::admitted_by \
  --start-from nucleus_cred_protocol::extracted::admission::clamp \
  --start-from nucleus_cred_protocol::extracted::admission::admit_upstreams \
  --start-from nucleus_cred_protocol::extracted::headers::header_policy \
  --start-from nucleus_cred_protocol::extracted::headers::forwarded_headers \
  --start-from nucleus_cred_protocol::extracted::headers::forwards_header \
  --start-from nucleus_cred_protocol::extracted::headers::guest_may_propose_header \
  --start-from nucleus_cred_protocol::extracted::headers::names_a_credential \
  --start-from nucleus_cred_protocol::extracted::headers::header_value_admissible
aeneas -backend lean -split-files ../../nucleus_cred_protocol.llbc -dest lean/generated/NucleusCredProtocol
```

The `.llbc` lands at the repository root. Two runs produced identical files.
Then `lake build` here (the library is a `@[default_target]`).

## Not yet done

* No CI job re-extracts and diffs this, so nothing yet fails when the Rust
  changes and this copy does not. Until one does, this is a snapshot of the
  code at the commit that last regenerated it.
* No theorem. `ci/egress-decisions.toml` counts a decision as proved only
  with a theorem over the extracted def and a Rust–Lean parity test.
