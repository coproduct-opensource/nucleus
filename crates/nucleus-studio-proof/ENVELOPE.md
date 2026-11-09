# Signed change envelope

This protocol binds the mathematical decision to the exact human-approved
change. It is being wired; the standalone contract result is not this envelope.

The existing subject's candidate field becomes SHA-256 over
`nucleus/studio/change-candidate/v2\n` followed by canonical JSON containing
`blueprint`, `compiled`, and `certificate_packet_sha256`. The last value is
SHA-256 of the canonical public contract packet. The WebAuthn challenge is
SHA-256 of the complete canonical subject, as the existing app-change ceremony
already signs. A signature over an unrelated packet cannot satisfy this binding.
Canonical numeric inputs must be natural safe integers (at most 2^53 - 1),
checked before JCS conversion. Otherwise JSON canonicalization could round a
large Lean natural into a different contract's commitment. Floats, negative
numbers and larger integers are refused, including in nested objects.

The public envelope includes the packet, candidate blueprint, full subject and
its digest, retained raw subject signature and public credential metadata,
claimed application time, expected after-state digest, and compressed per-app
proof. The semantic base is independently pinned. It contains no private key,
agent credential, business records or private source-binding preimage.

The verifier recomputes packet/candidate/source-definition commitments and
verifies the exact subject signature under the expected origin/RP. It checks
application before signed expiry, the signed counter metadata and unchanged
expected state digest for the admitted identity class. It then rechecks the
actual contract decision. A sealed result has no execution or publication right.

The host still supplies actual source/binding/state correspondence, enrollment,
Administrator membership, live agent scope and claimed wall time. Those facts
must remain a separate trusted tier; the signature establishes only that the
included key signed these exact bytes; enrollment is a host claim. Serving must recompute current
snapshots and run the native exact-approval/CAS gates before publication.

`verify_bytes` and Wasm `check_signed_studio_change` enforce a 16 MiB envelope
wire limit. The expected origin and RP come from verifier configuration, never
from the envelope. Run checking in a fresh disposable worker/process with a
deadline; a malformed kernel term can trap. Product worker and publication
wiring remain unfinished, so this protocol is not yet a deployed guarantee.

This immutable historical report is not an affine permission. It has no consume
operation and may be inspected repeatedly after the signed expiry; that expiry
constrains the claimed application time, not later inspection. Accordingly it
does not declare the repository's `must_use` affine-right marker or invent a
new execution validity interval. Actual approval consumption remains native.
