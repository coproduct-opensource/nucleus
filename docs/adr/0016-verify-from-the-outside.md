# ADR 0016 — Verify from the outside: a pod's launch is a TPM statement, checked where authority is granted

- Status: Proposed (2026-10-08)
- Tracks: North Star C9 ("verify from the outside"), milestone M6 of the eval-cell programme.
- Builds on: ADR 0011 (node evidence), ADR 0012 with A1/A2/A3 (TPM-resident keys, the
  assertion's tier), ADR 0013 (the eval cell), ADR 0014 §9 (`Demand::When(EvalCell)`,
  switched on in the PR that adds it).

## Context

C9 is NOT-YET. Each reason the ledger gives, re-checked on `main` at `827394f5a`:

| Ledger reason | On `main` | Evidence |
|---|---|---|
| The attested SVID is software-only. | **Holds.** `IdentityManager::compute_attestation` hashes the kernel, rootfs and config. `SelfSignedCa::sign_attested_csr` signs that hash with the node CA key. No TPM operation touches a launch. | `nucleus-node/src/identity.rs#fetch_attested_certificate` |
| The verifier runs only from the CLI. | **Holds, and is worse than stated.** `nucleus_identity::verify_attested_svid` (behind `SelfMeasuredBackend`, so behind `nucleus verify-attestation`) parses the leaf and reads the extension. **It never checks who signed the leaf.** A self-signed certificate carrying OID 1.3.6.1.4.1.57212.1.1 passes. This is the defect `sandbox_proof.rs` fixed for itself on 2026-09-29 (`VerifiedLaunch`), but the fix stayed private to the tool-proxy, so there are two deciders and the public one is the weak one (G-1). | `nucleus-identity/src/attestation.rs#verify_attested_svid` |
| `sandbox_proof.rs` is dead code. | **Stale.** `nucleus-tool-proxy` calls `sandbox_proof::verify_sandbox` at start-up and derives `ContainmentMode` from it. It is a guest-side self-check, though, so it is defence in depth, never the relying party: guest root can run a tool-proxy that skips it. | `nucleus-tool-proxy/src/main.rs` (`verify_sandbox`) |
| Firecracker only. | **Holds.** A pod on another tier gets a plain SVID, with only a `warn!` saying so. On the boot path, a failed measurement or a failed attested issue is also only a `warn!`, and the pod boots with a plain SVID. | `nucleus-node/src/pod_boot_identity.rs` |
| The round-trip test skips the UDS transport. | **Holds.** `attested_svid_is_served_and_verifier_reds_on_drift_and_absent` reads the cache directly. | `nucleus-node/src/identity.rs` tests |
| No in-toto provenance. | **Holds for the launch.** The release ships SLSA build provenance (`nucleus-vX.provenance.intoto.jsonl`), but nothing binds a launch measurement to a released artifact. | release workflow |
| OID PEN 57212 is unregistered. | **Holds.** This one is owner-only. | `nucleus-identity/src/oid.rs` |

Node evidence (ADR 0011) is what a TPM *does* sign today: a quote over the boot PCRs, bound
to the executor key and the JWKS digest. Since A2, the CA root is sealed to the boot PCRs at
rest. While the node runs, though, it is an in-memory Ed25519 key, and nothing the TPM signs
mentions a pod.

## Decision

The owner rule applies to each fork: take the strongest option, name its cost, and give the
weaker one only as the runner-up.

### D1. One verifier: `nucleus_identity::VerifiedLaunch` (G-1, C-1, C-2)

`VerifiedLaunch` moves from the tool-proxy into `nucleus-identity`, keeping its private
constructor. `VerifiedLaunch::verify(leaf, trust_bundle)` is the only way to mint one. It
checks the chain to the bundle first, then the launch extension, and both are required.

- Every consumer goes through it: the tool-proxy's `sandbox_proof`, the node's admission,
  `SelfMeasuredBackend`, the CLI, and each mTLS peer path (D4).
- `verify_attested_svid`'s extension-only path is **deleted**, not kept alongside in
  parity. The CLI gains a required `--trust-bundle` flag.

**Fate of `sandbox_proof.rs`: revived as a caller, not deleted.** Its tiering and its
`ContainmentMode` derivation stay, because a policy's `minimum_isolation` reads them. Its
private verifier is deleted.

*Runner-up:* delete `sandbox_proof.rs`. It is weaker because the executor would lose the
only typed source of its `MicroVM` containment claim. The claim would come back as a
hardcode, which is the defect `SandboxProof::containment` documents.

### D2. The launch is a TPM statement (rooted per ADR 0012)

At each launch the node takes a **launch quote**: a challenge-response quote
(`Freshness::Nonce`) from the same AK that signs its epoch evidence.

- **The nonce:**
  `SHA-256("nucleus-launch-v1" ‖ SVID SubjectPublicKeyInfo DER ‖ kernel ‖ rootfs ‖ config)`.
- **Storage.** The quote is stored by digest beside the epoch evidence and served on the
  anonymous evidence listener (`public_evidence`).
- **The SVID.** It carries the quote's digest in a new extension, `.1.7` (`.1.5` is the TPM hardware-rooting extension and `.1.6` the unmeasured-launch extension; see `nucleus-identity/src/oid.rs`). The quote binds
  the SPKI, not the certificate, so there is no circularity.
- **What the verifier checks.** `VerifiedLaunch` gains a closed
  `LaunchRoot { NodeCa, Tpm(Appraised) }`. For `Tpm`, it fetches the quote and recomputes
  the nonce from the leaf's SPKI and measurement. It then appraises the quote with the
  existing `nucleus_node_evidence::appraise` against an operator-chosen reference and
  anchors.
- **What it buys.** A stranger then holds: an AK anchored by a labelled anchor, which
  quoted an Attested node boot, which vouched for *this key* running *this measurement*.
  Compromising the CA key at runtime no longer forges a launch, because the forger also
  needs a quote over the forged SPKI from an AK on an Attested boot.

**Cost:** one TPM quote per launch, serialized on the attester mutex. Its latency is not
measured; S3 measures it and sets the budget. The guest floor does not move, because
nothing changes in the guest.

*Runner-up:* bind the CA public key into the epoch quote's `KeyBinding`. That costs nothing
per launch. It is weaker because the TPM then vouches for a key and never for a launch, so
a CA key exfiltrated from a running node still mints launches the evidence cannot tell apart
from real ones.

### D3. Eval cells verify at admission, now; standard pods are unchanged (ADR 0014 §9)

The semantics are `Demand::When(EvalCell)`, switched on in the PR that adds the
requirement. No guest row is added, because every check is host-side.

- **At create.** The node's current evidence must self-appraise **Attested**. This uses
  the A3 self-appraisal decider, `PlatformAttestation::attestation_now`, which the
  federation mint already uses.
- **At boot.** Before the VMM starts, the SVID the node is about to serve must pass
  `VerifiedLaunch::verify` against the node's trust bundle, and carry exactly the
  measurement the node took. A missing identity manager, a failed measurement or a failed
  issue is a refusal, never the `warn!` and plain-SVID fallback that standard pods keep.

**Cost:** an eval cell runs only on a node with a TPM, a reference manifest and a pinned AK.
Today that is the n2 Shielded recipe with `OperatorFetched`. No eval cell runs on a dev Mac,
in Lima without a swtpm pin, or on Apple container.

*Runner-up:* admit an Unattested node and record the tier on the receipt. It is weaker
because the cell's record would then promise a boot that nobody checked.

The **anchor class** the cell requires is any `Attested` tier, with the anchor labelled.
Requiring `CertificateChain` would be stronger. It is owner-only, though: no node we can
run today has a vendor AK or EK certificate (#3224), so requiring it would make eval cells
unrunnable everywhere.

### D4. Every mTLS peer path that grants authority verifies the launch at the handshake

Paths that grant authority on a pod SVID:

- the node's HTTPS API (`auth::spiffe_context_for_request`);
- the pod-peer tier (`nucleus-tool-proxy/src/auth.rs`);
- `nucleus-spiffe-hail`.

Each gets a rustls client-cert verifier wrapper that runs the chain check and then
`VerifiedLaunch`. The isolation profile goes into the SVID in a CA-signed extension, `.1.8`,
so a relying party without node state knows the peer is an eval cell. An eval-cell SVID
without a verified launch fails the handshake. A standard SVID that carries a launch must
verify; an absent launch is tolerated.

An xtask census holds the closed list of `TlsServerConfig` and `MtlsListener` sites, and
reds on an unlisted one (A-19: driven red by adding one).

*Runner-up:* a per-request middleware check. It is weaker because the connection exists and
routes run before the check. It would also put one decider in each router.

### D5. Coverage is stated, never a fallback

The tiers that cannot measure a launch (container, local, Apple VZ) are already refused for
eval cells (ADR 0013, rule 1). On those tiers a standard pod's SVID carries an explicit
`unmeasured` launch state instead of a silently plain certificate. A verifier that requires a
launch then refuses it by that name.

## Sequence to PROVED

Each step is one PR, with a definition of done (DoD) and an A-19 falsifier: red on the real
defect, then green when the fix is restored.

| Step | Definition of done | Falsifier |
|---|---|---|
| **S1. Eval-cell admission verifies (D1 move + D3).** | `VerifiedLaunch` lives in `nucleus-identity`, and `sandbox_proof` delegates to it. Create refuses an eval cell on a node that is not Attested, by name. Boot refuses an eval cell whose SVID fails `VerifiedLaunch`, or whose measurement differs, by name. Standard pods are unchanged. | Remove the `attestation_now` check, and the Unattested-node test goes green-admitted, so it reds. Remove the boot gate, and the no-identity eval cell boots, so it reds. A foreign-CA leaf with the right extension is refused, and reds if the chain check is removed. |
| **S2. The public verifier is the chain-checked one (D1 rest).** | `verify_attested_svid`'s extension-only path is deleted. `SelfMeasuredBackend` and `nucleus verify-attestation --trust-bundle` go through `VerifiedLaunch`. | An `rcgen` self-signed leaf with OID `.1.1` passes the CLI on `main`; it must red. |
| **S3. Launch quote (D2).** | The node quotes each launch. The digest goes into the SVID as `.1.7`, and the quote is served publicly. `LaunchRoot::Tpm` is appraised. Eval-cell boot requires `Tpm` at Attested. A swtpm fixture is checked in. Latency is measured and budgeted. | A quote over a different SPKI (certificate swapped) is refused. One byte of measurement drift is refused. Each check reds if its comparison is removed. |
| **S4. The mTLS paths (D4).** | The handshake verifier is on each listed path. The `.1.8` profile extension is in place. The census gate is live. | An eval-cell SVID with no launch completes a handshake on `main`; it must red. Adding an unlisted acceptor reds the census. |
| **S5. Coverage (D5).** | An `unmeasured` launch state is set on the non-VM tiers. | A require-launch verifier accepts a container pod's SVID; it must red. |
| **S6. UDS round trip.** | The served-SVID test drives `FETCH_SVID` over the real workload-API socket (the `pod_boot_identity_tests` harness), then `VerifiedLaunch`. | Serve the plain certificate, and it reds. |
| **S7. Launch provenance (in-toto).** | The release signs an in-toto statement with subject = kernel and rootfs digests, and predicate = the ledger commit and theorem set. The stranger's verifier checks a launch measurement against the statement's subject. | A rootfs digest that is in no signed statement is refused. |
| **S8. A stranger verifies.** | `docs/stranger-verification.md` gains "verify a pod's launch". It runs on a published escape-lane run, from public inputs only. This is M6's gate. | The runbook with the quote digest altered fails. |
| **S9. PROVED.** | The pure decision core of `VerifiedLaunch::verify`, with the launch-quote appraisal, is Aeneas-extracted. The theorem: accept ⇒ chain verified ∧ nonce = H(SPKI, m) ∧ m ∈ reference ∧ tier Attested. Signature verification is an axiom, and the theorem states it. The ledger row moves with its gate. | Drop a conjunct from the extracted function, and the theorem fails to check. |

S1 is the next PR. S2 and S6 are independent of S3. S4 needs S3, because the handshake
should check the TPM root rather than the CA. S9 needs S3 and S4.

## Owner-only

- **Register PEN 57212** with IANA, before any external-interop claim.
- **Hardware with a vendor AK or EK certificate**, to move the anchor from `OperatorFetched`
  to `CertificateChain`: C4A metal (quota denied, #3224), or metal on premises.
- **Whether eval cells require `CertificateChain`** once such hardware exists (D3).
- **Promoting the C9 row**, at S9.

## Consequences

- Until S3 lands, S1's boot check verifies a **software** root (the node CA). S1 makes the
  check live and fail-closed on the eval-cell path. It does not make it hardware-rooted, and
  the C9 note says so.
- Every eval cell now needs an Attested node, which narrows where eval cells run (D3, cost).
