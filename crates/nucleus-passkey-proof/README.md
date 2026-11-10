# Exact-subject passkey proofs

This public, standalone verifier checks the raw WebAuthn ES256 assertion over
an expected 32-byte subject digest. It has no controller, persistence, account
or network dependency. Its key, origin, relying-party ID and credential ID
come from the caller's enrolled registry; assertion claims cannot replace them.

Credential ID, challenge, origin, RP hash, user-presence and user-verification
flags, signature counter and DER signature are checked. Enrollment and current
Administrator membership remain host facts. Replay consumption and comparison
with a previously accepted counter belong to the caller's durable authority
boundary. `Verified` has a private constructor and supplies no workspace right.

The implementation was extracted from Gatehouse's exact-subject passkey
verifier. Gatehouse must delegate to this core when integrated, rather than
retain another cryptographic decider. The first fixture is an actual virtual
authenticator assertion captured from the Studio browser approval flow; it
contains only public key and signature material, never a private key.

Production source denies all seven totality lints. Native tests verify the
captured browser signature and refuse wrong subject, origin, RP, credential,
signature, counter, presence and verification flags, malformed/short data and
over-budget fields. Cryptographic primitives and codecs remain in the trusted
checker base; these lint declarations are not a Lean proof of their internals.
