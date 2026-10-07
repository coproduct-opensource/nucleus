# ADR 0012 — The federation issuer key lives in the TPM, bound to the measured boot

- Status: **accepted** (2026-10-07). Lands with its implementation in one PR.
- Tracks: limit-case hardening item A1 ("authority comes from the TPM and the measured
  boot, never from possessing a file"). A2 (the Ed25519 node keys) and A3 (the assertion
  carries the evidence epoch and tier) build on it; see the end of this record.
- Rests on: [ADR 0010](0010-a-credential-minted-per-exchange-never-stored.md) (the issuer
  key and its rotation), [ADR 0011](0011-node-evidence-what-booted.md) (the AK, the quote,
  the verifier), [ADR 0007](0007-make-the-defect-unwritable.md) (rule ids cited below).
- Applies to: `nucleus-node-evidence` (`tpm_key`, the attester side; `key_attestation`,
  the verifier side), `nucleus-federation` (`custody`, `keyring`), `nucleus-node`
  (`node_evidence`, `keys`), `nucleus-cli` (`federation rotate --tpm`, `issuer --export`),
  `nucleus-audit` (`verify-node-evidence --jwks --federation-key-attestation`).

## Context

A node that federates signs ES256 assertions with one P-256 key, and every provider that
registered the node's JWKS accepts what that key signs (ADR 0010). Until now the key was a
`0400` PKCS#8 file in the state directory. A file is a credential that travels: anyone
holding a copy of the disk, a snapshot, a backup or a copied image can mint this issuer's
assertions from anywhere, for as long as the providers trust the JWKS. This is not
hypothetical. The attested-journey runs of 2026-10-06 and 2026-10-07 copied a development
host's federation key onto a cloud VM so that the existing provider registrations would
accept it, and that worked first time. The copy was the deployment step.

ADR 0011 gave the node a TPM attester: an AK, quotes over the boot PCRs, and a stranger's
verifier. The TPM can do more than vouch for what booted. It can hold the key itself, and
use it only while the boot is the one it vouched for.

## Decision

### What is bound, and to what

On a node configured with a TPM (`--node-evidence-tpm`), the federation key is created
**in the TPM**:

- **Parent.** A storage primary in the owner hierarchy, derived from a fixed template:
  ECC P-256, AES-128-CFB, `restricted | decrypt | fixedTPM | fixedParent |
  sensitiveDataOrigin | userWithAuth | noDA`, zero `unique`. The TPM re-derives the same
  parent from its owner seed on every boot, so nothing about it is stored.
- **Key.** ECDSA P-256 / SHA-256 with `fixedTPM | fixedParent | sensitiveDataOrigin |
  noDA | sign`. `userWithAuth` is **clear**, so the user role (which `Sign` needs) is
  reachable only through the policy. `adminWithPolicy` is clear too, so the admin role is the
  empty password. The admin role can only `Certify` the key or change its password, and
  neither of those signs anything.
- **Policy.** `authPolicy = PolicyPCR(SHA-256 bank, PCRs {0, 2, 4, 7, 8, 9, 14}, their
  values when the key is created)`. The digest is computed in software from a `PCR_Read`
  by `policy_pcr_digest`, the same function the verifier uses (G-1). The TPM then checks it
  independently at every signature, by running `PolicyPCR` itself. So a mistake in that
  computation produces a key that never signs, never one that signs unbound. The function is
  also pinned by golden vectors from an independent stack: tpm2-tools 5.6
  `tpm2_createpolicy --policy-pcr` against libtpms.
- **On disk:** only `TPM2B_PRIVATE` (the TPM's encryption and integrity wrapping, under the
  parent's seed), `TPM2B_PUBLIC`, and the PCR list, in `jwt_svid_p256_tpm_key{,.next,.prev}.json`.
  The private scalar never leaves the TPM.
- **Signing** (`TpmP256Signer`) runs `Load`, `StartAuthSession` (policy, unbound,
  unsalted), `PolicyPCR` with an empty `pcrDigest`, then `Sign`, every time. With an empty
  `pcrDigest` the TPM extends the session with the PCRs' current values, so a boot state that
  moves under a running node stops its signatures from that moment. `Sign` then fails with
  `TPM_RC_POLICY_FAIL`.

### The PCR set, and why

The set must name the code that decides what runs, and must reproduce across a reboot into
the same code. It is chosen from measurements, not from a template. The checked-in vTPM
fixtures (ADR 0011, 2026-10-05 and -06) are quotes from three Shielded VM instances of one
image, one of them rebooted with an added kernel parameter:

| PCR | measures | three instances, one image | reboot with an extra parameter | bound |
|---|---|---|---|---|
| 0 | firmware code | equal | equal | **yes** |
| 1 | platform configuration (SMBIOS, boot variables) | **different on every instance** | — | no |
| 2 | option ROM code | equal | equal | **yes** |
| 3 | option ROM configuration | equal (no events) | equal | no: configuration, not code |
| 4 | boot manager and EFI applications (shim, boot loader, EFI-stub kernel) | equal | equal | **yes** |
| 5 | GPT and boot-variable data | equal | **changed** | no: moved without the code moving |
| 6 | wake events | equal (no events) | equal | no: not code |
| 7 | Secure Boot state and its databases | equal | equal | **yes** |
| 8 | boot loader commands, kernel command line | equal | changed (it is the parameter) | **yes** |
| 9 | files the boot loader read: kernel, initrd, its configuration | equal | changed (`grub.cfg` changed) | **yes** |
| 10 | IMA | different at every quote | — | **never** |
| 14 | shim's MOK state | equal | equal | **yes** |

PCR 10 is excluded on principle: it moves every time IMA measures a file, so no key could be
created against its final value. PCRs 8 and 9 are what stop an attacker who boots the
node's own image with `init=/bin/sh`, or with another initrd, from using the key. They are
also why an ordinary kernel or initrd upgrade is a new key (below). 11–13 carry nothing on
this boot chain. A UKI with systemd-stub would put its PCR 11 here.

`BOOT_POLICY_PCRS` is one constant in `nucleus-node-evidence::key_attestation`. The attester
creates keys against it, and the verifier refuses a policy that leaves any of it out
(`PolicyTooNarrow`).

### Custody: TPM unless waived by name

`nucleus_federation::KeyCustody` is `Tpm(TpmCustody) | File(FileCustody)`, and
`FileCustody` is `NoTpmConfigured | Waived`. There is no `Default` (B-1), and no `Option`
whose `None` means "a file" (B-2). One function decides it from the flags
(`NodeEvidenceArgs::federation_key_custody`, G-1):

| `--node-evidence-tpm` | `--allow-federation-key-in-file` | custody |
|---|---|---|
| set | absent | **TPM** |
| set | present | file, `Waived`: logged at start-up as a warning, and recorded as "file" with the reason in every custody statement the node publishes |
| unset | absent | file, `NoTpmConfigured` |
| unset | present | **refused**: a waiver that waives nothing is a misconfiguration (B-5) |

The waiver is a flag and never an environment variable, the Landlock waiver's rule: ambient
configuration is not a waiver.

Rotation (stage, promote, retire) is the same state machine as before, over whichever
layout the directory holds. A TPM-custody directory stages only TPM keys
(`rotate --stage --tpm <device>`), so rotation never brings a file key in. The custody is
never crossed. A file directory under TPM custody stops the node with an error that names
the waiver. A directory holding both layouts is refused (`MixedCustody`). Nothing is
converted. Moving a key into the TPM makes a new key, and upstreams must be told about it.

A TPM key whose policy does not match the boot the node finds itself in can never sign
there. At start-up the node checks this in software (`TpmCustody::usable_now`), and replaces
the key the way it already replaced an unreadable file key: it logs a warning that upstreams
which registered the old `kid` will refuse until they are updated.

### Key attestation: a stranger can check it

Every epoch, the node's AK certifies each published TPM key (`TPM2_Certify`, qualifying data
`SHA-256("nucleus-federation-key-attestation/v1/certify")`), once per `kid`. The statements
form one document, `nucleus-federation-key-attestation/v1`:

```json
{ "profile": "nucleus-federation-key-attestation/v1",
  "keys": [ { "kid": "…",
              "custody": { "tpm": { "public": "<TPM2B_PUBLIC>", "parent_public": "<TPM2B_PUBLIC>",
                                    "policy_pcrs": [0,2,4,7,8,9,14],
                                    "certify_attest": "<TPMS_ATTEST>", "certify_signature": "<TPMT_SIGNATURE>" } } } ] }
```

A file key is `{"file": {"reason": "…"}}`. The node stores the document at
`<state_dir>/node-evidence/federation-keys.json`, and also under its own SHA-256 in the
evidence store, which the anonymous listener already serves (`/v1/evidence/{sha256}`).
It serves the latest at `GET /v1/node/federation-keys` on the API listener, and
`nucleus federation issuer --export` publishes it beside the JWKS as
`.well-known/nucleus-federation-key-attestation.json`.

`nucleus_node_evidence::appraise_federation_keys(evidence, policy, jwks, attestation)`
appraises the evidence itself (C-2: the PCR values and the AK it reads are ones the appraisal
verified, so it cannot be handed unquoted PCRs). Then, for each JWKS key, it checks:

1. the AK signed the certification. Nothing in it is read before that check.
2. the certification is a `TPM_ST_ATTEST_CERTIFY` over the federation-key domain;
3. the certified Name is `0x000B || SHA-256(TPMT_PUBLIC)` of the published public area.
   The Name covers the point, the attributes **and the `authPolicy`**, so none of the three
   can be changed after certification;
4. that point is the JWK's point;
5. the attributes are the ones above: `userWithAuth`, `adminWithPolicy`, `decrypt` and
   `restricted` clear, `fixedTPM`, `fixedParent`, `sensitiveDataOrigin` and `sign` set;
6. the qualified Name puts the key under the published storage primary **in the owner
   hierarchy**, not the NULL hierarchy that external (software-made) objects load into;
7. the policy's PCRs are quoted, cover `BOOT_POLICY_PCRS`, and `authPolicy ==
   PolicyPCR(those PCRs, their QUOTED values)`.

The result is `TpmBound { policy_pcrs, name }`, `NotTpmResident { reason }` (the node said
"file") or `Unstated` (no statement for that `kid`; absence is not a pass, A-5). A false
statement is a `KeyRefusal` that names what was false. `nucleus-audit
verify-node-evidence --jwks J --federation-key-attestation K` prints the EAR and the
per-key verdicts, and exits 0 only when the platform is `Attested` **and** every key is
`TpmBound`. A key bound to a boot nobody vouched for is bound to nothing a relying party
trusts, and an attested boot proves nothing about a file key.

### PolicyAuthorize: considered, not adopted here

A plain `PolicyPCR` key is bricked by every change to the bound PCRs, which means every
kernel, initrd or boot-loader upgrade. systemd-measure and `systemd-cryptenroll
--tpm2-public-key` avoid that with `PolicyAuthorize`: the key's `authPolicy` names an
authority key. A new boot state is approved by that authority signing its `PolicyPCR`
digest, so the key survives an upgrade the authority approved.

It is the right next step, and it is not small:

- **It changes what a stranger verifies.** "Signs only in the boot state this quote
  measured" becomes "signs in any boot state the authority ever approved." The verifier
  would have to check the authority key's anchor, the signed approval, and that the quoted
  values are among the approved ones. A plain `PolicyPCR` key is checkable from the quote
  alone.
- **It needs predicted PCR values.** systemd signs predictions for PCR 11, which a UKI
  build can compute from the artifacts it ships. PCRs 0–9 of a cloud VM include the
  provider's firmware (PCR 0) and the boot chain's event sequence. Nothing in a nucleus
  release can predict them, so the approval would come from the operator observing a booted
  instance, which is weaker than a build-time prediction.
- **More TPM surface.** `LoadExternal`, `VerifySignature`, `PolicyAuthorize`, tickets,
  and on the verifier side a signature chain to check.

So the cost of an upgrade today is a new key. The node detects it, logs it and creates the
key at first boot, and the operator publishes the new JWKS. Upstreams registered by discovery
pick it up within their JWKS cache lifetime. Inline registrations must be updated by hand.
**Follow-up:** a `PolicyAuthorize` key whose authority is the operator's release-signing
key (policyRef `nucleus-federation`). Each approval would be published to a transparency log,
so a stranger can enumerate every boot state the key could ever sign in.

## What this closes

- **A stolen disk, snapshot, backup or image cannot mint federation credentials.** The
  wrapped blob loads only under this TPM's owner seed: on another TPM, `Load` fails with
  `TPM_RC_INTEGRITY`, measured on libtpms. Even on this TPM, it signs only in the measured
  boot state. Booting the same disk with another kernel, initrd, boot loader or command line
  (PCRs 4, 8, 9) gives `TPM_RC_POLICY_FAIL`, as does disabling Secure Boot or changing its
  databases (PCR 7).
- **Root on the running node cannot exfiltrate the key.** There is nothing to copy. What it
  can copy, the wrapped blob, is the case above.
- **A stranger can verify all of this** from the quote, the JWKS and the custody statement,
  without trusting the node. The AK anchor is ADR 0011's, labelled in every result.

## What this does not close

- **A running root compromise can still drive the TPM while the boot state matches.** The
  TPM becomes a signing oracle for the attacker, for as long as they keep root on this boot.
  The difference from a file key is that the oracle stops when they lose the machine or it
  reboots into a changed state. Nothing extends a PCR on a detected compromise yet. That
  would be a revocation lever.
- **The binding is the boot, not the userspace.** IMA (PCR 10) is not in the policy. A
  replaced `nucleus-node` binary on an unchanged boot can use the key. The quote's IMA log
  shows the replacement, and the platform tier turns `Contested`, which is exactly why
  `nucleus-audit` requires `Attested` beside `TpmBound`. But the TPM itself would still sign.
- **PCRs 1, 3, 5 and 6 are not bound.** A change that touches only platform configuration,
  the partition table or wake events leaves the key usable. That is deliberate, measured
  above, and stated in every `TpmBound` verdict's `policy_pcrs`.
- **The TPM is the root.** A vTPM is the hypervisor's, and its operator can do anything the
  vTPM can. The AK anchor for a cloud vTPM is `OperatorFetched` (ADR 0011). A cleared owner
  hierarchy (`TPM2_Clear`) destroys the key. That is an availability loss, not a compromise.
- **The Ed25519 node keys** (executor, approval, cert root, task issuer) are still files.
  Sealing them to the same policy is **A2**, a separate change. The TPMs this runs on do
  not implement Ed25519, so those keys become sealed blobs that are unsealed into memory,
  not TPM-resident keys, and the claim A2 can make is correspondingly weaker.
- **Migration** from a file key to a TPM key is a new key, not a rotation. A mixed-custody
  rotation (stage a TPM `next` while a file `current` signs) would avoid a JWKS gap, and is
  not built.

## How A3 and the Gatehouse minter build on this

- **A3: the assertion carries the epoch and the tier.** An assertion that says "the node
  was in evidence epoch E, appraised Attested" is only as good as the key that signed it. A
  file key can sign that claim from anywhere. With this ADR, the signing key is certified by
  E's AK and cannot sign outside E's boot state. A relying party that checked the key once
  (`TpmBound` against E's quote) can then treat the claim in each assertion as backed by the
  TPM, not by the node's word. A provider's attribute condition on the claim (the
  workload-identity recipe A3 documents) inherits that.
- **The Gatehouse minter** appraises a node in full before it trusts the node's issuer: the
  evidence against its reference, and `appraise_federation_keys` over the issuer's JWKS and
  custody statements. It can pin each node's certified Name, and it can refuse a JWKS key
  whose verdict is not `TpmBound`. That makes "this node's issuer key cannot leave the node"
  a precondition of minting, not an assumption.

## Evidence for this decision

- **libtpms (swtpm 0.7.3), `nucleus-node-evidence/tests/federation_key_swtpm.rs` and
  `nucleus-federation/tests/tpm_custody_swtpm.rs`.** Each starts its own swtpm processes,
  and both are `#[ignore]`d without one:
  - A key signs, and the signature verifies under its JWK.
  - After `PCR_Extend(8)`, `Sign` fails with `TPM_RC_POLICY_FAIL`. Extending PCR 16, which
    is outside the policy, changes nothing.
  - A blob moved to a second swtpm fails `Load` with `TPM_RC_INTEGRITY`.
  - The AK's certification verifies, and the verifier refuses each of these: an
    `authPolicy` byte flipped (Name mismatch), another TPM key's public area under this
    certification (Name mismatch), a byte flipped inside the signed attest (signature), and
    a key re-quoted after its boot state moved (policy mismatch).
  - A TPM-custody keyring stages, promotes and retires, the running signer follows the
    promote, and it stops signing when PCR 9 moves.
- **Software-TPM unit tests, which run in CI** (`key_attestation_tests.rs`). Each refusal
  is driven from an honest certification that is first shown to be `TpmBound`:
  - signed by another key;
  - a rewritten `authPolicy`;
  - another key's public area;
  - the wrong JWK;
  - each attribute: `userWithAuth`, `adminWithPolicy`, `fixedTPM`, `fixedParent`,
    `sensitiveDataOrigin`, `sign`, `decrypt`, `restricted`;
  - a policy over another boot state;
  - a policy that leaves out PCR 14;
  - a restated PCR list;
  - an unquoted PCR;
  - the NULL hierarchy;
  - a non-storage parent;
  - another qualifying domain;
  - a quote instead of a certification;
  - refused evidence;
  - an unknown profile.

  The file statement and the absent statement are separate tests, each shown never to pass.
- **CLI fixtures, which run in CI** (`nucleus-audit/tests/federation_key_cli.rs`). These
  are the real TPM bytes of two captures with `examples/federation_key.rs`: one on swtpm,
  and one on a cloud Shielded VM's vTPM (x86, Ubuntu 24.04, kernel 7.0, the provider's ECC
  AK template).
  - On the vTPM, the AK the evidence carries hashes to the AK the provider's API reported
    for that instance. `verify-node-evidence` gives `Attested` with anchor
    `operator_fetched`, and the key is `tpm_bound` to 0, 2, 4, 7, 8, 9, 14.
  - After `PCR_Extend(8)`, the vTPM refused to sign. The re-quote's boot log no longer
    replays, so the evidence is refused. With the log set aside, the key's policy is visibly
    not over the quoted values.
- **A-19.** Each probe below injects one defect, and the named tests turn red. With the
  defect restored, the same tests are green, and the tree is clean afterwards.

  | probe | red |
  |---|---|
  | `r` and `s` swapped in the TPM signature | swtpm sign round trip |
  | `BOOT_POLICY_PCRS` without PCR 8 | swtpm extend-stops-the-key (signing succeeded after the extend) |
  | a blob that fails `Load` replaced by a fresh key | swtpm blob-moved (signing succeeded on the other TPM) |
  | certified Name not compared | rewritten `authPolicy`; swtpm certification |
  | `authPolicy` not compared with `PolicyPCR(quoted)` | another boot state; swtpm certification |
  | certification signature not checked | signed by another key; swtpm certification |
  | a file statement read as `TpmBound` | file key is not TPM-resident |
  | `userWithAuth` accepted | empty-password attributes |
  | qualified Name not compared | NULL hierarchy |
  | `BOOT_POLICY_PCRS` coverage not checked | policy leaves out PCR 14 |
  | signer accepts a file key under TPM custody | custody is never crossed |
  | a TPM without the waiver gives file custody | node custody decision |
  | `nucleus-audit` exits 0 with a file key | CLI file-key test |

## References

- TPM 2.0 Library, Part 1 (Names, qualified Names, policy sessions), Part 2
  (`TPMA_OBJECT`, `TPMS_CERTIFY_INFO`), Part 3 (`TPM2_PolicyPCR` 23.7, `TPM2_Certify`,
  `TPM2_Create`, `TPM2_Load`, `TPM2_Sign`).
- TCG PC Client Platform Firmware Profile (the PCR allocation), and the TCG provisioning
  guidance's SRK template.
- systemd-measure(1), systemd-cryptenroll(1) `--tpm2-public-key`: signed `PolicyAuthorize`
  policies over predicted PCR 11.
- RFC 9334 (RATS), RFC 9711 (EAT).
