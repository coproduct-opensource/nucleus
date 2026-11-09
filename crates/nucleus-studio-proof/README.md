# Studio contract decisions

This standalone crate rechecks a bounded Studio Equipment change through
nanoda. It has no private-controller dependency, account, credential, network
client or retained business records. It is an implementation checkpoint, not
the complete Studio change certificate or a deployed verification page.

The pinned semantic prefix exports the actual `StudioCertificate.checkTyped`,
`typed_sound` and `typed_future_execution` declarations and their dependencies.
A per-app theorem proves the closed decision `checkTyped packet = true`.
The Rust producer proposes `Eq.refl true`; nanoda must reduce the exact closed
decision to true for that term to type-check. The checker binds that theorem type to the supplied
visible fields and full contracts, then rechecks every exported declaration.
An unrelated theorem, changed semantic prefix, substituted app packet or
ill-typed proof cannot mint `VerifiedContract`.

There is no per-app Lean compiler or proof search in this producer. The one literal wire schema is used in both directions. It is a codec in the
trusted checker, not a second implementation of the Equipment compiler. The
nullary/record constructor names and field order correspond to the actual
Studio Lean types. The Rust producer proposes literals; it does not decide
compilation or migration admissibility. Missing fields refuse, except the
native protocol's existing default of empty `data.exclusions`.

The decision proves compilation correspondence, equal execution effects and
an identity, lossless migration commuting with every finite future execution
from every valid retained state. It compares captured authority strings; it
does not establish that the host captured actual authority. The supplied
fixture uses a synthetic unchanged-authority label.

Credential enrollment, passkey approval, live grants, correspondence to the
hosted executable and storage, and whether the visible definition expresses
human intent are outside this result. There is no proof of another migration
class or app family here. The application service has not yet been wired to
create these witnesses before publishing changes.

## Reproduce

Run `cargo test --release --manifest-path crates/nucleus-studio-proof/Cargo.toml`.
The fixtures preserve a successful real closed decision, the generic semantic
base, substituted-packet refusals and a false proof with an unchanged statement.
Disabling the nanoda call makes the false-proof test fail. Restoring it passes.

The Lean source is `olog/studio-db/kernel/StudioCertificate.lean`, imported
from the actual Studio runtime modules, on Lean `v4.34.1`. The official
lean4export revision is `076e8e57707e813375e8f9da8bf989799ace9680`, with its
toolchain set to `v4.34.1`. Export format is `3.1.0`.
Nanoda is pinned to `6ba649836ff52755d77bbe5bc732a129b7173486`.
Only `propext`, `Classical.choice`, and `Quot.sound` are permitted; unpermitted
axioms are hard errors. `Lean.trustCompiler` is not permitted.

`studio-proof-produce BASE_NDJSON PACKET_JSON NEW_DELTA_GZIP` constructs and
independently checks the decision before writing a compressed per-app proof.
It needs no Lean toolchain. A native test passes its valid decision and refuses
all four seeded edits through nanoda's `def_eq` check: widened borrower access,
dropped retained field, added erase effect and mismatched visible column label.

For diagnostic comparison, `studio-proof-witness PACKET_JSON WITNESS_LEAN`
creates untrusted Lean source using `decide +kernel`. Compile it against the
actual Studio modules, then export roots in
this order: `StudioCertificate.checkTyped`, `StudioCertificate.typed_sound`,
`StudioCertificate.typed_future_execution`, `StudioCertificateWitness.accepted`.
The first three roots alone produce the semantic base. `studio-proof-check
BASE_NDJSON PROOF_NDJSON PACKET_JSON` checks the full result without an account.
`studio-proof-pack-fixture` produces deterministic compressed base/delta files.

The semantic prefix SHA-256 is
`f4951fc8d0a41899554782c069926033c6219532d200b855f43fb16fb589759f`.
The app packet remains bounded at 16 MiB and literal lists at 4,096 entries.
The fixed semantic base has a separate 32 MiB bound and the app proof suffix
has a 16 MiB bound; this does not change the hosted kernel's input or deadline
limits. Compressed input and expanded sizes are both bounded.

## Browser checkpoint, 2026-11-09

Build the library for `wasm32-unknown-unknown`, then use wasm-bindgen `0.2.129`
with `--target web`. The browser export `check_studio_change` uses the same
binding and nanoda implementation, accepting compressed base, compressed
per-app suffix and packet bytes. A malformed term may trap; the browser must
discard that worker and report refusal. A product worker/deadline UI remains
to implement.

A fresh Playwright context loaded the Wasm and fictional fixtures, then CDP
disabled its network. The offline call rechecked 5,539 declarations in
2,564.7 ms. Changing a supplied view label was refused as a packet mismatch.
Replacing the theorem's proof while retaining its exact statement trapped
with `RuntimeError: unreachable` and the test discarded the instance.
These are browser library tests, not a public URL or finished product page.

The subsequent native Rust producer generated a 5,130-byte compressed suffix
without invoking Lean. A second fresh offline browser context rechecked its
5,538 declarations in 2,536.4 ms, returning proof SHA-256
`1fdeab80d5f31c645b885cb0304acc58597670cebae91c38b2c6b0fc38915e2b`.

The root prepush affected-crate selector does not include this standalone
workspace. Run its explicit test and Clippy commands as well as the mandatory
root prepush checks; a root green alone does not cover this checker.
