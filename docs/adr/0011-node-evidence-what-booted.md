# ADR 0011 — A receipt carries third-party-verifiable evidence of what booted the node that signed it

- Status: **accepted** (2026-10-05). PR-1 lands the evidence format and the verifier with
  this ADR. PR-2 adds the node attester and the receipt binding. PR-3 is the live run,
  recorded in `docs/findings/attested-node-live-run.md`.
- Tracks: #2706 (L-5, attestation; North Star confidentiality row C9, "verify from the
  outside").
- Rests on: the measured facts in `docs/findings/attested-node-gcp-spike.md` (draft PR #3224).
- Applies to: a new crate `nucleus-node-evidence` (types and the verifier), `cargo xtask
  node-reference-manifest`, and later `nucleus-node` (attester) and `nucleus-audit`
  (`verify-node-evidence`, composite verdict in `verify-execution`).

## Context

The North Star position is that a stranger can check a receipt without trusting the
operator. A receipt today proves *which key* signed it and what that key's policy allowed.
It does not prove *what software held the key*. An operator who swaps the node binary, boots
a different kernel, or turns enforcement off still signs valid receipts. Only hardware can
vouch for the boot, and only if what it vouches for is tied to the receipt's signer.

Before this ADR the only "attestation" was a launch claim the node's own CA signs into a
guest's SVID (the DICE-OID extension, read by `nucleus-tool-proxy::sandbox_proof`). An audit
found that path once accepted a self-signed certificate carrying the OID; that was fixed on
2026-09-29 (`VerifiedLaunch`, minted only after a chain check). It remains the node vouching
for its own launches. Nothing beneath it vouched for the node.

The spike measured one cloud's VMs (2026-10-05) and found:

1. The provider's signed attestation token is issued only to confidential VMs, which have no
   KVM, and it carries no boot measurements at all — so it can neither host Firecracker nor
   say what booted.
2. A plain vTPM quote over the PCRs, plus the TCG boot event log and an IMA log, *does*
   identify the kernel image, the command line and each measured userspace binary, works on
   both x86 and Arm Shielded VMs, and can bind a key through its qualifying data.
3. That vTPM's attestation key (AK) has **no certificate**. It is anchored only by the
   provider's API, which reports the AK's public key to an authenticated project member.
4. A `nested virtualization` flag is silently stored and not honoured on Arm and confidential
   shapes; only the guest itself can say whether `/dev/kvm` exists.

## Decision

### Roles (RFC 9334, RATS)

- **Attester**: the node. It asks its TPM for a quote and publishes the evidence.
- **Verifier**: `nucleus_node_evidence::appraise`, and the audit CLI built on it. Pure Rust,
  no `libtss2`, no `ring`, no C, so it compiles to wasm. Since the browser-verifier change
  (below, "As built: the stranger's verifiers") `sdks/verifier-js` embeds it and
  `sdks/verifier-py` links it, so a change to this crate moves that SDK's pinned wasm
  digest.
- **Relying party**: whoever checks a receipt. It supplies everything the evidence is
  compared against — the executor key the receipt names, the freshness requirement, the
  reference manifest, its own trust roots and operator pins. The evidence supplies none of
  them.

### Evidence (EAT-shaped JSON, RFC 9711)

`NodeEvidence` (`eat_profile: "nucleus-node-evidence/v1"`) carries the AK as a
`TPM2B_PUBLIC`, the `TPMS_ATTEST` and `TPMT_SIGNATURE` of a quote over SHA-256 PCRs (boot:
0–9 as available, plus 14 for shim's MOK state; IMA: 10), the values of those PCRs, the TCG
crypto-agile boot event log, a narrow IMA log, the key binding, the freshness value, and the
**claimed** AK anchor. Each log is either attached or absent *with a reason*.

### Key binding

The quote's qualifying data is `SHA-256` over a domain tag and three length-prefixed, tagged
fields: the executor public key, the federation JWKS digest (or an explicit "not federated"),
and the freshness value (challenge nonce, or epoch counter + time). The encoding is
injective and pinned by a golden vector computed independently of the crate. This is what
lets a stranger tie a receipt's signer to the attested boot: a quote taken for one key, or
one challenge, cannot be presented for another. The verifier checks both that the evidence's
binding equals the relying party's expectation (`BindingMismatch`) and that the TPM signed
exactly that binding (`QualifyingData`).

### Freshness

A replayed quote must not appraise as affirming (the gap arXiv 2608.03534 found in a
deployed verifier). Two modes:

- **Challenge-response**: the verifier sends a 16–64-byte nonce; the node quotes over it. The
  verifier compares the nonce *it sent*. Any other nonce is `Expired(NonceMismatch)`.
- **Epoch**: for offline checking, the node re-quotes on an interval over (counter, time);
  receipts reference the epoch evidence digest; the verifier enforces a maximum age at the
  receipt's time (`Expired(TooOld)`) and a maximum future skew (`Expired(FromTheFuture)`).

Rewriting the freshness claim without re-quoting is a `QualifyingData` refusal, in both
modes. The epoch time is the node's own clock: signed through the qualifying data, not
measured by the TPM. That is recorded as a limit.

### AK anchor — a closed enum, labelled in every result

`CertificateChain` (verified offline to a root the relying party trusts) >
`OperatorFetched{source}` (the relying party holds a pin for this AK that an operator fetched
from an authenticated source such as a cloud API — the operator vouching, the weakest
anchor) > `None`. The anchor is resolved **only** against the relying party's inputs. A
claimed chain that is internally broken, or certifies another key, is a false claim and the
evidence is refused (`FalseAnchor`), never downgraded. A chain to an untrusted root, or an
operator claim without a matching pin, resolves to `None` and the tier is `Unattested`. An
AK must also carry `restricted | sign | fixedTPM | fixedParent | sensitiveDataOrigin` and not
`decrypt`: a key that is not restricted can sign a forged `TPMS_ATTEST`, so no pin makes its
quotes evidence (`NotAnAttestationKey`).

### Reference values

A reference manifest (`nucleus-node-reference/v1`, CoRIM field naming —
draft-ietf-rats-corim — in JSON) lists exact PCR pins, Secure Boot state, EFI application
digests (PCR 4), files the boot loader loaded (PCR 9: kernel image, configuration), the
kernel command line (PCR 8: exact, an exact parameter set, or — weaker, it misses an *added* parameter, measured in PR-3 — required parameters; a dm-verity root hash goes here),
and an IMA allowlist of the node's files by install path with required paths. Every check is
an explicit `required` or `not_checked` *with a reason*; an omitted check is a parse error,
not a pass, and every `not_checked` item is reported beside the verdict.
`cargo xtask node-reference-manifest` writes it from files or `sha256sum` listings —
never from the event log it will be compared with.

*Since the release-manifest change:* every release publishes
`nucleus-<version>-<arch>.node-reference.json`, written by
`cargo xtask release-reference-manifest emit` from the shipped musl `nucleus-node` and the
upstream Firecracker archive at the pinned version. It is signed with `cosign sign-blob`
like every other asset, so its digest is in the public Sigstore log and the inclusion proof
ships in `<asset>.sigstore.json` (the publish-measurements-to-a-log pattern of arXiv
2409.03720). It holds only the IMA allowlist (`nucleus-node` required; `firecracker` and
`jailer` allowed). Every boot check is `not_checked`, because the release publishes no
host image. `node-reference-manifest --ima-from-manifest` folds it into an operator's
boot pins. Nucleus's own transparency log (`nucleus-lineage`) is not used for this: it
would need a hosted log and a signing key that the release workflow does not have, and
Sigstore already gives an independently operated log. The stranger's procedure is in
`docs/stranger-verification.md`.

Following Keylime's measured-boot and IMA policy approach, the IMA log is expected to be
**narrow**: the node's policy measures executables on its own install filesystem (by
`fsuuid`) plus whatever the platform's Secure Boot policy adds (kernel modules), and every
measured file must be allowlisted.

### Results (EAR / AR4SI tiers, draft-ietf-rats-ear)

`appraise` returns `Result<Appraisal, Refusal>`, two layers with different consequences
(ADR 0007 A-8):

- `Refusal` — not evidence: bad signature, PCR values that do not hash to the quoted
  digest, a log that does not replay, a binding mismatch, a false anchor.
- `Appraisal.tier`: `Attested` (affirming) only when the anchor is not `None`, the evidence
  is fresh, and there are no divergences; `Contested` (contraindicated) when measurements
  diverge from the reference, each divergence named; `Expired` (warning) when not fresh;
  `Unattested` (none) when nothing ties the quote to a TPM — or, in the receipt verdict, when
  there is no evidence at all (e.g. a host with no TPM). `Unattested` is an honest tier, not
  an error. A required check that could not be made is a `NotEvaluable` divergence: "could
  not look" is never "looked and it was fine" (ADR 0007 A-2).

`Appraisal` has private fields and is minted only by `appraise` (C-1, C-2); the tier is a
total `match` over (anchor, freshness, divergences), so a tier that skipped one of the three
does not compile (E-2 — driven red in PR-1's A-19 probes).

### Receipts (PR-2)

The execution receipt and admission record bind the node evidence digest (SHA-256 of the
evidence document bytes) and epoch. `nucleus-audit verify-execution` reports a composite
verdict, authorization result × platform tier; `nucleus-audit verify-node-evidence` appraises
evidence on its own. A node without a TPM records `Unattested` explicitly and never claims
more.

### Attester (PR-2)

Linux only, feature-gated. It speaks raw TPM 2.0 commands over `/dev/tpmrm0` (no `tss-esapi`,
no C dependency): `NV_Read` of the provider's AK template, `CreatePrimary` under the
endorsement hierarchy, `PCR_Read`, `Quote`, password sessions only. The marshalling shares
the verifier's parsers, the verifier is tested against quotes from an independent stack
(`tpm2-tools`), and the attester is tested by feeding its output to that verifier.

### As built (PR-2)

- `nucleus-node --node-evidence-tpm /dev/tpmrm0 [--node-evidence-ak-template
  nv:<index>|default-ecc] [--node-evidence-anchor operator:<source>|none]
  [--node-evidence-epoch-secs N]`. Unset, every receipt records
  `Unattested { reason }`. Set, an unusable TPM or a failed first quote stops startup.
- Epoch documents are stored under `<state_dir>/node-evidence/<sha256>.json`, and the
  counter persists across restarts. A failed re-quote keeps the previous epoch in force,
  so receipts signed in the meantime age into `Expired` and never anything stronger.
- Public routes, since the evidence is not secret: `GET /v1/node/evidence` (the epoch in
  force), `GET /v1/node/evidence/{sha256}` (by the digest a receipt names), and
  `POST /v1/node/evidence/challenge {"nonce": hex}` (one at a time; a concurrent request
  gets 429).
  *Since:* these sit behind the API listener's mTLS handshake, so a stranger
  could not reach them (live run, finding 3). `--public-evidence-addr`
  (`NUCLEUS_NODE_PUBLIC_EVIDENCE_ADDR`, opt-in) opens a separate listener —
  server-authenticated TLS, no client certificate — that serves only
  `GET /v1/evidence/{sha256}` (re-hashed before it is sent, at most 4 MiB) and
  `GET /v1/node/keys` (the executor public key). No challenge route (a quote is
  TPM work; it stays on mTLS), no "latest", no listing, nothing about pods.
  Global token bucket (`--public-evidence-requests-per-sec`, default 20) and 32
  requests in flight. `--public-evidence-tls-cert/-key` give it a certificate
  for a DNS name; otherwise it presents the node's SVID. See
  `crates/nucleus-node/src/public_evidence.rs`.
- `ExecutionClaim.node_platform` is `Unattested { reason } | Evidence { evidence_sha256,
  epoch }` and is signed inside the receipt. A receipt from before this field reads as
  `Unattested`.
- `nucleus-audit verify-node-evidence` exits 0 only for `Attested`. `verify-execution`
  reports `node_platform.verdict` as a second axis next to authorization, and with
  `--require-attested` it fails unless the platform is `Attested`. Evidence supplied
  beside a receipt that says `Unattested` never upgrades it.
- The admission record does not yet carry the digest; the execution receipt does.
- The federation binding is the SHA-256 of `serde_json::to_vec(jwks)` from the node's
  keyring, taken at each quote when `--federation-issuer` is set.

### As built: the stranger's verifiers

- `nucleus_node_evidence::report(evidence, reference, relying_party)` takes the three
  documents a stranger holds as bytes and returns `appraised { evidence_sha256, ear }` or
  `refused { evidence_sha256, refusal }`. It adds no decision: it parses, calls `appraise`,
  and serializes. The relying party's inputs are one JSON document (`RelyingParty`:
  `binding`, `freshness`, `trust_roots`, `operator_pins`, `now`), every field required, so
  "trust no pin" is written `[]` and never reached by omission (B-1).
- `sdks/verifier-js` exposes it as `verifyNodeEvidence(evidenceBytes, reference,
  relyingParty)` through its wasm build; `sdks/verifier-py` as `verify_node_evidence`.
  Both return the crate's own serialization (F-1); neither restates a tier. Evidence is
  taken as bytes, never a parsed object, because `evidence_sha256` must be the digest a
  receipt names.
- Parity: `crates/nucleus-node-evidence/tests/fixtures/parity/cases.json` lists seven
  cases over the real-TPM fixtures (live epoch-4 `Attested`, an hour later `Expired`,
  without a pin `Unattested`, another executor key refused, the perturbed reboot
  `Contested`, the PR-1 vTPM challenge `Attested` and replayed `Expired`). The Rust test
  checks each status and writes/compares the golden report; the JS (through the wasm
  build) and Python bindings must reproduce each report exactly. A-19: making `report`
  check the evidence against its own binding instead of the relying party's turns the
  Rust, native-JS and wasm-JS parity tests red on the other-executor-key case.
- Cost: the release wasm grew from 1,335,516 to 2,079,937 bytes (457 KB to 700 KB
  gzipped), the P-256/P-384/RSA verifiers and the X.509 parser.

## Evidence for this decision (PR-1)

- Real cloud vTPM fixtures (x86 Shielded VM, Ubuntu 24.04, kernel 7.0): an ECC AK re-created
  from the provider's NV template has the **same** public key the provider's API reports for
  the instance — the operator-fetched anchor, measured. Quotes, event log (11 PCRs replayed,
  Secure Boot and kernel command line authenticated from their event digests, kernel image
  digest equal to `sha256sum` of `/boot/vmlinuz`) and a narrow IMA log (two node binaries +
  the platform's kernel modules) appraise `Attested` with anchor `OperatorFetched`.
- The same evidence is `Expired` under another nonce or past the epoch age, `Contested`
  against a reference that requires a verity parameter or another kernel or omits a binary,
  `Unattested` without the pin, and refused with a flipped PCR, a rewritten log digest, or
  another executor key.
- A libtpms (swtpm) RSA-2048 RSASSA quote covers the RSA path.
- 13 A-19 probes, each neutralising one check in the verifier, turn the suite red.

## Limits (what this does not claim)

- **Host only.** It measures the host boot and the node's own files. What runs inside a
  Firecracker guest is not measured by the host TPM; per-pod evidence (the rest of #2706)
  builds on this.
- **IMA records a load**, not that the loaded file is still what runs; appraisal/enforcement
  is not used.
- **`OperatorFetched` is the operator's word.** It is the only anchor the spike's cloud
  offers for VMs that can run KVM. A hardware-anchored AK (an EK certificate on bare metal,
  or a provider CA-issued AK certificate) is `CertificateChain` and needs no operator trust;
  the Arm bare-metal shape that might provide one was blocked by quota and is untested.
- **The epoch time is the node's clock**; a node compromised after boot could misreport it.
  The TPM's `resetCount`/`clock` are recorded in every appraisal for correlation.
- **EFI application digests** (PCR 4) are Authenticode hashes; the reference generator does
  not compute them yet, so they are `not_checked` in the fixture reference.
- ~~The verifier is not yet compiled to wasm or embedded in the JS/Python verifiers.~~
  Since the browser-verifier change: it is (see "As built: the stranger's verifiers").
  What remains is publishing what a stranger feeds it — reference manifests with
  releases, and evidence reachable without a node credential.

## References

- RFC 9334 — Remote ATtestation procedureS (RATS) Architecture.
- RFC 9711 — The Entity Attestation Token (EAT).
- draft-ietf-rats-ear — EAT Attestation Results (AR4SI trustworthiness tiers).
- draft-ietf-rats-corim — Concise Reference Integrity Manifest.
- arXiv 2608.00801 — hardware-rooted attestation for AI-agent evidence.
- arXiv 2608.03534 — nonce-freshness gap in a deployed verifier (a replayed quote appraised
  as affirming).
- Keylime — measured boot and IMA runtime policies (allowlist of file digests, boot event
  log replay against PCRs).
- TCG PC Client Platform Firmware Profile (crypto-agile event log); TPM 2.0 Library Part 2
  (`TPMS_ATTEST`, `TPMT_SIGNATURE`, `TPMT_PUBLIC`).
