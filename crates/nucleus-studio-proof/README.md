# Studio contract decisions

This standalone crate rechecks a bounded Studio Equipment change through
nanoda. Its native checker needs no private controller, account, credential,
network or retained business records. The optional Rust browser page preloads
public assets and an explicitly shared certificate with credentials omitted;
proof checking itself runs in a disposable offline worker. This is the first
Equipment/identity-migration class, not all Studio families or a deployed page.

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

## Browser page checkpoint (2026-11-09)

`web.rs` implements presentation, file selection and the worker protocol in Rust.
The only JavaScript supplied by this source is wasm-bindgen's module-loader
invocation; it contains no checking or authority policy. A fresh Blob worker
loads its module/Wasm from already cached object URLs, receives bounded bytes,
and returns the sealed checker's report. Success, refusal, trap and deadline all
terminate the instance. A monotonic result-time check also refuses late results
when browser scheduling delayed its ten-second timer.

Selection/context edits invalidate previous results. Empty, oversized or failed
file reads cannot reuse previous certificate bytes. Resource readers bound
decoded Fetch stream bytes and cancel on excess; they do not assume that HTTP
Content-Length exists or counts decoded data. CSP permits only same-origin
assets and local Blob loading. No cookies or authenticated requests are needed.

For local acceptance with Rust and wasm-bindgen CLI 0.2.129 installed:

```sh
cargo build --release --target wasm32-unknown-unknown --lib --manifest-path crates/nucleus-studio-proof/Cargo.toml
wasm-bindgen --target web --out-dir crates/nucleus-studio-proof/pkg crates/nucleus-studio-proof/target/wasm32-unknown-unknown/release/nucleus_studio_proof.wasm
cargo run --release --manifest-path crates/nucleus-studio-proof/Cargo.toml --bin studio-proof-preview -- "$PWD/crates/nucleus-studio-proof"
```

Open `/proof/verify` at the printed loopback address, set the expected origin to
`https://studio.example` and RP ID to `studio.example`, then choose
`fixtures/equipment.signed.json`. This fictional example uses a deterministic
software test signer, not an enrolled human or live account. The native test
pins the entire fixture to its producer. Disconnect networking before Verify.
Adding `--encoded` to the preview command exercises HTTP gzip without a length
header. This preview helper exposes only a fixed asset list at exact loopback
Host; it never opens application state or accepts writes.

Fresh Playwright contexts verified the signed packet offline in 2,293 ms and
the gzip/no-length variant in 2,328 ms (5,538 declarations). Packet substitution
refused; a false proof trapped, was discarded, and a new valid check recovered.
A deliberately stalled worker timed out (10,401 ms including UI automation),
then recovered with zero live workers. A simulated late monotonic observation
refused before its timer fired. Desktop and 390px mobile screenshots show no
horizontal overflow. Oversized selection reuse and missing-length loading were
each first reproduced red, then checked after correction. An oversized streamed
resource now refuses without starting a worker. Native tests pass five cases in
8.76s; native and Wasm warnings-denied Clippy and the standalone audit pass.

Issuing real app certificate snapshots, serving these assets in the host,
Keep integration, all nine families and additional migration classes remain
unfinished. Expected origin/RP come from the verifier/user, never the capsule.
See `ENVELOPE.md` for the distinction between independently rechecked clauses
and trusted host/storage/enrollment/time claims.

Playwright CLI 1.63.0 also passed the complete auto-loaded fictional example at
`/proof/example` in WebKit, at desktop and iPhone 13 sizes. Its HAR contains only
GETs for public loopback fixture assets/certificate and local Blob resources;
no account or stored browser state was supplied. This is a WebKit compatibility
check, separate from the Chromium network-disabled checks above. It is not a
real production capability: the preview's all-zero fixture path serves only the
public deterministic example and never opens tenant state.

A delayed-Wasm browser test also reproduced early file selection being ignored.
Attachment now imports an already-selected native file through the same handler;
the delayed-load selection subsequently verifies offline. File readiness never
stands in for required checker assets. All three browser defects are recorded
as observation/framing laws in the corresponding Olog schema.
# Definition-only certificates and Keep

`definition::Certificate` has the explicit purpose
`studio-app-definition-v1`. It independently rechecks compilation for an
identity packet, matching its blueprint and stored-contract hashes against
expectations supplied by the recipient. A Keep caller must take those hashes
from the selected app in the reviewed Keep subject; copying expectations from
the certificate itself would not bind it to that subject. The browser export
is `check_studio_definition`.

This purpose carries no passkey approval and makes no claim about earlier edits,
migrations, ownership transfer, current authority or live records. It cannot
be substituted for the version-2 approved-change envelope. The same definition
evidence may remain applicable after Keep only when the blueprint and contract
commitments still match. Storage correspondence and the caller's reviewed
subject remain separate trust boundaries. The service producer and Keep UI
wiring are not yet implemented for this purpose. The pinned child now accepts
`studio-proof-certify --definition BLUEPRINT_SHA256 CONTRACT_SHA256`, reads an
unproved definition certificate on bounded stdin, and returns
`{certificate, checked}` only after producing and independently rechecking its
proof. Existing `ORIGIN RP_ID` mode still requires a signed change envelope.
The process regression checks exact retained input, independently rechecks the
returned proof, and refuses wrong blueprint/contract commitments, an already
proved input, and definition-only input presented as an approved change.
The release process regression passes in 3.73 seconds, including the second
independent verification. Tests exercise the actual
producer and independent kernel; disabling the reviewed-hash comparison admits
a substituted blueprint and makes the regression fail.
