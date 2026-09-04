# Aeneas extraction of the identity/card verifiers (#2452)

*Design note, 2026-09-04. Status: JWT-SVID claims decision landed; the other two
are scoped here and tracked as follow-ups.*

Three "verified" constructors share the shape of `verify_certificate`: a real
cryptographic check, then a pure decision, with only Rust module privacy
between "verified" and "fabricated". The decision (#2452, owner) was to extend
the existing Aeneas→Lean pipeline to them rather than invent a second proof
approach, and, per the toolchain check recorded on the issue, to extract the
**pure decision core** of each with parity tests binding it to production,
because the pinned Charon 0.1.223 / Aeneas d71d2e3 still emit `Iter::fold` as an
opaque axiom and the signature primitives (`ed25519-dalek`, `ring`, `sha2`) are
outside the extractable subset.

This note names, for each verifier, the extraction-safe subset boundary and the
theorem to prove. It is the first acceptance criterion of #2452; the second
(one of the three landed as a real extracted, CI-rebuilt, axiom-audited theorem)
is met by §1.

## The shared recipe

1. **Carve the pure core** into a `String`/iterator/closure-free module under an
   `extracted/` directory of a crate that already has a pipeline
   (`nucleus-github-oidc` for the OIDC family, `portcullis-core` for the
   lattice family). Slices of bytes and integer index loops are fine;
   **slices of slices are not** (`&[&[u8]]` is a nested borrow, which Aeneas
   rejects outright) and neither is any `Iterator` adapter.
2. **Call through**, do not mirror: production calls the extracted core on the
   live path. A parity proptest keeps the pre-refactor clause, lifted verbatim,
   as the oracle, so the refactor is checked to have changed nothing.
3. **State theorems over the generated defs**, never a hand model. Straight-line
   cores get closed theorems; index loops come out as the Aeneas `loop`
   combinator (`partial_fixpoint`), which does not reduce under `simp`, so loops
   are covered by the Rust parity tests and the gap is disclosed, not `sorry`d.
4. **Gate it**: the workflow re-extracts on every change, builds the theorem
   against the fresh extraction, requires positive `#print axioms` evidence,
   and fails on `sorryAx` or any opaque external axiom.

## 1. `verify_jwt_svid` (control plane) — LANDED

**Function.** `nucleus_control_plane_server::auth::verify_jwt_svid`: EdDSA
signature over the compact-JWS input, then the claims decision.

**Boundary.** Signature verification stays in production. The claims decision
is extracted as `nucleus_github_oidc::extracted::jwt_svid_claims`:
`decide_claims(exp, nbf, now, skew, aud_ok, sub_ok)` (straight-line, in
production's check order), `has_prefix` (subject prefix) and `bytes_eq`
(per-audience equality). The audience **fold** stays in production because its
input is `&[&[u8]]`; it applies the extracted `bytes_eq` per element and
passes the result in as `aud_ok`.

**Theorems** (`crates/nucleus-github-oidc/lean/JwtSvidClaimsProofs.lean`, over
the generated `decide_claims`):

- `admit_sound`: `Admit` implies the audience matched, the prefix matched,
  `exp + skew` is representable and not below `now`, and if `nbf` is present
  then `now + skew` is representable and `nbf` is not above it.
- `aud_mismatch_fails_closed`, `sub_mismatch_fails_closed`: a failed
  membership or prefix check never admits.
- `admit_complete`: all four predicates holding gives `Admit`.
- `not_yet_valid_has_nbf`: `NotYetValid` is only raised with `nbf = some _`.
- `expired_first`, `not_yet_valid_second`, `audience_third`, `subject_last`:
  the first failing predicate, in production's order, is the verdict.

**Not claimed.** The signature check; the audience fold; the byte loops as
closed Lean theorems (parity proptests cover them).

## 2. `verify_card` / `verify_card_json` (agent card) — scoped, follow-up

**Function.** `nucleus_agent_card::verify::verify_card`: JCS canonicalisation
of the received document minus `signatures`, detached-JWS ES256 verification of
*any* signature entry that carries a `kid`, then `apply_nucleus_policy`.

**Boundary.** Canonicalisation (`serde_json` + JCS) and ES256 are outside the
subset. The pure core to extract is the **acceptance combinator**
`verify_any_signature`'s decision: given the per-entry outcomes as a slice of
outcome codes (`u8`: verified / missing-kid / bad-signature / key-mismatch),
return accept iff the slice is non-empty and some entry verified. The
per-entry check stays in production. A second, separate core is the nucleus
claims policy in `apply_nucleus_policy` once it is restated over plain
booleans/enums (extension present, claims parse, required fields present).

**Theorems.** (a) Fail-closed on emptiness: an empty outcome slice never
accepts. (b) Soundness: accept implies some entry's outcome is `verified`.
(c) Single-witness sufficiency: one verified entry accepts regardless of
other failures (this is the co-signing/rotation property the module docs
promise). (d) For the policy core: a `VerifiedCard` is constructible only when
every required claim predicate holds.

**Caveat to surface.** The combinator's decision is over a slice, so it is a
loop; expect the closed theorems to need the per-step form (as
`collapse_lossy_step` does for the sanitiser) unless the combinator is restated
as a fold over a fixed small bound.

## 3. `SvidAttestationBackend::verify_svid` (identity assurance) — scoped, follow-up

**Function.** `SelfMeasuredBackend::verify_svid` (and the TPM DevID backend):
parse the served SVID chain, extract the launch-attestation extension, check it
against `AttestationRequirements`, then build a `VerifiedAttestation` carrying
the backend's declared assurance level, its `proves`/`not_proven` claim
profile, and the subject key binding.

**Boundary.** PEM/X.509 parsing and extension extraction are outside the
subset. Two pure cores:

- `AttestationRequirements::verify`: three allow-list membership checks
  (kernel, rootfs, config hash). Restated over fixed-width byte arrays and
  index loops, with the allow-lists as flat `&[u8]` plus a stride, since
  `&[[u8; 32]]` is fine but `&[&[u8]]` is not.
- The claim-profile normalisation: the result's assurance level equals the
  backend's declared level, and the `not_proven` set is exactly the profile's
  complement; nothing is upgraded by the verifier.

**Theorems.** (a) Fail-closed: `require_attestation = true` with no extension
never yields an attestation (production returns an error; the extracted
decision returns a refuse code). (b) Requirements soundness: accept implies
each non-empty allow-list contains the corresponding measured hash. (c)
Level ceiling: the produced assurance level is never above the backend's
declared level, and `proves ∩ not_proven = ∅`.

**Finding to record while scoping.** `AttestationRequirements::verify` treats
an **empty** allow-list as "do not check", so a deployment that sets no
`allowed_kernel_hashes` accepts any kernel hash. That is the intended
"unconfigured" semantics, but it is the same empty-means-everything shape that
was a bug in `PathLattice` (#2474). The extracted theorem (b) makes the
semantics explicit; whether the default should be fail-closed is an owner call
and is not changed here.

## Order of work

§1 is done. §2's acceptance combinator is the smaller core and should go next;
§3's requirements check is mechanical but needs the flat-allow-list restating
before Charon will accept it. Each lands as its own PR with its own theorem
file and axiom audit, following the `aeneas-oidc-spiffe.yml` freshness
pattern.
