# ADR 0012 — The federation issuer key lives in the TPM, bound to the measured boot

- Status: **accepted** (2026-10-07). Lands with its implementation in one PR. Addendum
  A2 (2026-10-07, same day): the Ed25519 node keys are sealed at rest. Addendum A3
  (2026-10-07, same day): every assertion states the node's platform tier. Both are at the
  end of this record.
- Tracks: limit-case hardening item A1 ("authority comes from the TPM and the measured
  boot, never from possessing a file"). A2 (the Ed25519 node keys) and A3 (the assertion
  carries the evidence epoch and tier) build on it; see the end of this record.
- Rests on: [ADR 0010](0010-a-credential-minted-per-exchange-never-stored.md) (the issuer
  key and its rotation), [ADR 0011](0011-node-evidence-what-booted.md) (the AK, the quote,
  the verifier), [ADR 0007](0007-make-the-defect-unwritable.md) (rule ids cited below).
- Applies to: `nucleus-node-evidence` (`tpm_key`, the attester side; `key_attestation`,
  the verifier side), `nucleus-federation` (`custody`, `keyring`), `nucleus-node`
  (`node_evidence`, `keys`), `nucleus-cli` (`federation rotate --tpm`, `issuer --export`),
  `nucleus-audit` (`verify-node-evidence --jwks --federation-key-attestation`). A3:
  `nucleus-federation` (`attestation`), `nucleus-node` (`federated_credential`,
  `node_evidence`).

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
- **The Ed25519 node keys** (executor, approval, cert root, task issuer) were still files
  when this decision was taken. **A2** (the addendum below) seals them to the same policy.
  The TPMs this runs on do not implement Ed25519, so those keys are sealed blobs unsealed
  into memory, not TPM-resident keys, and the claim A2 makes is correspondingly weaker.
- **Migration** from a file key to a TPM key is a new key, not a rotation. A mixed-custody
  rotation (stage a TPM `next` while a file `current` signs) would avoid a JWKS gap, and is
  not built.

## How A3 and the Gatehouse minter build on this

(A3 is built: see addendum A3 below.)

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

## Addendum A2 (2026-10-07): the node's Ed25519 keys are sealed at rest

The node holds four Ed25519 keys beside the federation key: the executor key (receipts),
the approval key (`/v1/approve`), the certificate root (every pod's `LatticeCertificate`)
and the task issuer (session capability tokens). Until A2 each was a `0400` PKCS#8 file in
the state directory, so a copied disk carried all four. The TPMs this runs on do not
implement Ed25519, so these keys cannot be what the federation key is, a key the TPM signs
with. What the TPM can do is **seal** them.

### What is sealed, and to what

- **Object.** Each 32-byte seed is the sensitive data of a `TPM_ALG_KEYEDHASH` object with
  a NULL scheme (a sealed data object), created under the same storage primary as the
  federation key. Attributes: `fixedTPM | fixedParent | noDA`. `userWithAuth` is clear, so
  `Unseal` (a user-role command) is reachable only through the policy. `adminWithPolicy` is
  clear. `sensitiveDataOrigin` is clear because the node supplies the data, and `sign`,
  `decrypt` and `restricted` are clear because the object is data, not a key.
- **Policy.** The same `PolicyPCR` over the same set, `BOOT_POLICY_PCRS` = {0, 2, 4, 7, 8, 9,
  14}, computed by the same `policy_pcr_digest` (G-1). Nothing about the set is restated.
- **On disk:** `<role>_signing_key.sealed.json`, holding `TPM2B_PRIVATE`, `TPM2B_PUBLIC`,
  the PCR list, the Ed25519 public key, and how the key came to be sealed (`generated` or
  `migrated_from_file`). There is no key file.
- **At start-up** the node loads each object, runs `PolicyPCR` in a fresh policy session and
  `Unseal`s it. The seed is held in a wiping container (`Zeroizing`), and every TPM command
  and response buffer in the raw layer is wiped on drop. The `SigningKey` built from the seed
  zeroizes itself on drop (`ed25519-dalek`'s `zeroize` feature).

### Custody

`NodeKeyCustody` is `Sealed(TpmEndpoint) | File(NoTpmConfigured | Waived)`. There is no
`Default`. The truth table is the federation key's, and it is written once: one function,
`decide`, serves both custody decisions.

| `--node-evidence-tpm` | `--allow-node-keys-in-file` | node keys |
|---|---|---|
| set | absent | **sealed** |
| set | present | files, `Waived`: logged at start-up and recorded in the custody statement |
| unset | absent | files, `NoTpmConfigured` |
| unset | present | **refused** (B-5) |

**Why a waiver of its own, not the federation key's.** The two decisions cost different
things. Moving the federation key into the TPM makes a new key, and every upstream that
registered the old one must be told, so an operator may reasonably keep
`--allow-federation-key-in-file` for a while. Sealing the node keys keeps every public key,
so it costs nothing. One waiver would make the free protection wait on the expensive one.
The likely transition state, a federation key still in a file and node keys sealed, needs
the two to be separate.

The custody is never crossed:

- File custody refuses a directory that holds a sealed key. It does not regenerate over it.
- Sealed custody does not run on a key file. A TPM that cannot be reached or refuses to seal
  stops the node with an error that names the waiver.

### Migration keeps the public keys

An existing node has key files. Under sealed custody, each role key is migrated in place:

1. Read the key file.
2. Seal the same seed.
3. Write the sealed blob atomically: a temporary file is written and `fsync`ed, renamed, and
   the directory is `fsync`ed.
4. Read the blob back from disk and `Unseal` it.
5. Only if it unseals to the same seed, delete the key file, and `fsync` the directory.

The node logs each migration, and the custody statement records `migrated_from_file`.
Because the public key is unchanged, every receipt, approval and certificate the key ever
signed still verifies, and nothing that pinned it needs to change. This is where A2 differs
from the federation key, whose move into the TPM is a new key.

A crash at any point leaves a usable key:

- **Before the rename:** the key file is intact, and a stale temporary is discarded on the
  next attempt.
- **After the rename, before the delete:** both exist. The next start unseals the blob and,
  if the file holds the same key, deletes it. If the file holds a different key, the node
  refuses to choose and stops.
- **When the round trip fails,** the blob just written is removed, the key file stays, and
  the node stops.

### A changed boot

A sealed key the TPM refuses for its policy (`TPM_RC_POLICY_FAIL`: a kernel, initrd, boot
loader, command line or Secure Boot change) or its integrity (`TPM_RC_INTEGRITY`: another
TPM's blob) is moved aside to `<file>.unusable-<time>`, kept, and replaced by a new sealed
key, with a warning. This is the same availability rule as an unreadable key file, and the
same rule as the federation key. Unlike a regenerated file key, the old blob is kept:
booting back into the state it was sealed in and moving it back recovers the old identity.
Any other TPM failure stops the node and is never a reason to change identity.

The consequence is the federation key's: until `PolicyAuthorize` (above), an upgrade of the
bound boot chain is four new node keys. Receipts signed before the upgrade still verify
under the old public keys. Anything that pinned an old key has to be told the new one: an
executor registration, `--cert-trust-anchors`, or a running pod's approval key. Pods do not
survive the reboot an upgrade needs anyway.

### What the node states

The node keeps `node-evidence/node-keys.json` (`nucleus-node-key-custody/v1`) and serves it
at `GET /v1/node/key-custody`. For each role it lists the public key and either
`tpm_sealed`, with the sealed object's `TPM2B_PUBLIC`, `policy_pcrs`, `policy_digest`,
`origin` and `sealed_at`, or `file` with the reason. A reader holding a quote of
`policy_pcrs` can recompute `policy_digest` from the quoted values.

**What it is not, yet.** The statement is the node's own word. The AK does not certify the
sealed objects, and `nucleus-audit` does not appraise the statement. Even certified, a
sealed object's Name would prove "this TPM holds a data object under boot policy X". It
would not prove that the object's contents are the executor key: the `unique` field of a
sealed object hashes the data with a secret salt, so nothing public links the two. That
link would be the node's word in any design that seals rather than holds the key. Such a
design is the follow-up below, and it is a smaller claim than the federation key's
`TpmBound`.

### What A2 closes, and what it does not

**Closes.** A disk, snapshot, backup or image taken away from the machine carries no usable
node key:

- The blob loads only under this TPM's owner seed.
- Even on this TPM, it unseals only in the measured boot state.
- A migrated node keeps no key file, and the custody statement says which keys were
  migrated.

**Does not close.** The sealing protects the keys **at rest only**, and that is a weaker
claim than the federation key's:

- **A running node holds the unsealed keys in RAM.** Root on the running node can read them
  from the node's memory and copy them anywhere, and they stay valid off the machine
  indefinitely. The federation key is different: it never leaves the TPM, so root on a
  running node can only use it as a signing oracle while it keeps the machine.
- **Root can also unseal the blob directly** while the boot state matches. It needs no
  password, only the PCRs, and the policy does not name the `nucleus-node` binary: IMA
  (PCR 10) is not bound. This includes a stolen whole machine, as opposed to its disk,
  booted normally into its own state. Whoever gets root there gets the keys.
- **The unseal crosses the TPM interface in the clear.** The policy session is unsalted, so
  `Unseal`'s response is not parameter-encrypted. On a vTPM that interface belongs to the
  hypervisor, which holds the TPM anyway. On a discrete TPM it is a bus that an attacker
  holding the machine could probe during boot.
- **Wiping is best effort.** The seed lives in a zeroizing container and the TPM buffers are
  wiped, and `ed25519-dalek` zeroizes the `SigningKey`. The certificate root is also handed
  to `ring` as an `Ed25519KeyPair`, and the node does not control how long that copy lives.
  Swap and core dumps are not addressed here.

### Evidence for A2

The swtpm tests start their own swtpm processes and are `#[ignore]`d without one:

- **libtpms (swtpm 0.7.3), `nucleus-node-evidence/tests/sealed_secret_swtpm.rs`:**
  - A secret round-trips, twice. Its `authPolicy` is `PolicyPCR` over the current boot
    values, and neither stored part contains it.
  - After `PCR_Extend(8)`, `Unseal` fails with `TPM_RC_POLICY_FAIL`. PCR 16 changes nothing.
  - On a second swtpm, `Load` fails with `TPM_RC_INTEGRITY`.
- **`nucleus-node` `keys::tests`, the swtpm ones:**
  - A sealed key unseals across a restart and signs, and no byte of the seed is on disk.
  - After `PCR_Extend(8)` the old blob is set aside and a new key replaces it.
  - A state directory moved to another TPM yields no key equal to the original.
  - Migration keeps all four public keys and deletes the files.
  - A key file outlives a blob that does not verify.
  - A crash before the rename, or between the rename and the delete, completes with the same
    key. A different key beside the blob is refused.
- **Unit tests, which run in CI:**
  - File custody refuses a sealed key.
  - A TPM node without the waiver refuses to run on its key file, and leaves it untouched.
  - The custody decision table, including that the federation waiver does not waive the node
    keys.
  - A sealed public area with `userWithAuth`, `adminWithPolicy` or `sign` set, or with
    `fixedTPM` or `fixedParent` clear, or without a digest policy, is refused.

**A-19.** Each probe below injects one defect, and the named tests turn red. With the
defect restored the same tests are green, and the tree is clean afterwards.

| probe | red |
|---|---|
| the sealed bytes are not the key (first byte dropped) | swtpm round trip; node unseal-and-sign, migration, crash, moved-disk and verify tests |
| the seal's policy leaves out PCR 8 | extend-stops-the-unseal, at the TPM layer and in the node |
| a migration leaves the key file behind | moved disk (the original key came back on another TPM); migration; crash |
| a migration makes a new key | migration keeps the public key; crash; verify |
| the key file is deleted before sealing | key file outlives a blob that does not verify; TPM node refuses to run on a key file |
| a blob accepted without unsealing what is on disk | key file outlives a blob that does not verify |
| an interrupted migration is not finished | crash mid-migration (after the rename) |
| a stale temporary blocks the retry | crash mid-migration (before the rename) |
| a TPM without the waiver gives files | both custody decision tables: the federation key's turns red too, because `decide` is shared |
| a TPM failure falls back to the key file | TPM node refuses to run on a key file; crash; verify |
| file custody reads past a sealed key | file custody refuses a sealed key |
| `userWithAuth` accepted in a sealed public area | sealed public area without its policy |

**Live vTPM run** (2026-10-07). One Spot n2 Shielded VM in us-east1-b, Ubuntu 24.04 with
kernel 7.0, created and deleted under the automation identity. `nucleus-node`, built x86_64
musl from this change, ran against `/dev/tpmrm0`, each start for 25 s:

1. **Without a TPM:** four `.der` keys. The statement says `file`, "no TPM is configured".
2. **With `--node-evidence-tpm /dev/tpmrm0`:**
   - four "migrated … with the SAME public key" log lines;
   - no `.der` file left, four `.sealed.json` files;
   - the statement lists the same four public keys, byte for byte, as `tpm_sealed`,
     `migrated_from_file`, policy PCRs 0, 2, 4, 7, 8, 9, 14.
   - The `policy_digest` `bc7fa99d…16fc` equals `tpm2_createpolicy --policy-pcr -l
     sha256:0,2,4,7,8,9,14` (tpm2-tools 5.6) on the same TPM: an independent computation of
     the policy.
3. **Restart with the TPM:** the keys unseal, and the public keys are unchanged.
4. **Restart without the TPM flag:** refused, "the custody is never crossed".
5. **After `tpm2_pcrextend 8`:** for each key, "cannot be unsealed: it is sealed to another
   boot state". The node takes that branch only on `TPM_RC_POLICY_FAIL`, so the warning shows
   the vTPM refused for the policy. Each old blob is kept as `.unusable-<time>`. Four new keys
   are sealed under a new policy digest, and none of the public keys is unchanged.

### Follow-ups

- **AK certification and appraisal of the sealed objects.** `TPM2_Certify` each sealed
  object every epoch, as for the federation key. Then teach `nucleus-audit` to appraise the
  statement against the quote, so a stranger can say "the executor key is sealed under
  boot policy X". As stated above, the link from the object to the public key would remain
  the node's word.
- **A salted session for `Unseal`,** with response parameter encryption, so the seed does
  not cross a discrete TPM's bus in the clear.
- **`PolicyAuthorize`,** shared with the federation key, so an approved upgrade keeps the
  node keys.
- **Node keys in the evidence binding.** The quote binds the executor key only. The
  approval and certificate-root keys could be bound the same way.

## Addendum A3 (2026-10-07): the assertion states the platform

An assertion signed by a TPM-bound key (above) is good evidence of *which* node signed it.
A relying party that issues credentials also wants to know *what state* that node was in,
and to refuse a node that is not freshly `Attested`. A3 puts that on every assertion.

### The claims

Four flat string claims, on every assertion (profile §1 and §8):

| claim | value |
|---|---|
| `nucleus_att_tier` | `attested`, `contested`, `expired` or `unattested` |
| `nucleus_att_epoch` | the evidence epoch counter, or `none` |
| `nucleus_att_time` | that epoch quote's time, Unix seconds, or `none` |
| `nucleus_evidence_digest` | SHA-256 of that epoch's evidence document, or `none` |

They are strings because provider rules match top-level strings (ADR 0010 §3), and a CEL
condition converts them with `int()`.

### Where the tier comes from

The **self-appraisal path** is `TpmNode::self_appraise` in `nucleus-node`, which calls
`nucleus_federation::NodeAttestation::of_current_evidence`. At each mint
(`PodFederation::exchange`, through `FederatedSource::attestation_now`):

1. It reads the epoch document in force back from the evidence store, by the digest in
   force. These are the bytes a relying party fetches by the same digest.
2. It runs `nucleus_node_evidence::appraise` on that document **at the mint time**. The
   inputs are the operator's reference manifest (`--node-evidence-reference`), the operator's
   AK pin (`--node-evidence-ak-pin`, with the source from `--node-evidence-anchor
   operator:<source>`), the binding the node's quotes carry now, and a maximum age of one
   epoch plus 30 s.
3. The tier is that `Appraisal`'s, mapped by one exhaustive function (`ClaimedTier::of`, E-1).

Nothing caches the result. `NodeAttestation`'s fields are private: a tier other than
`unattested` can be built only from an `Appraisal`, and only `appraise` mints one (C-1). The
platform source is attached to the issuer once, after the attester starts. The attester's
first quote binds the issuer's JWKS, so the issuer must exist first. An issuer with no source
attached states `unattested`.

### Could not look: `unattested`, not a refusal to mint

A node with no TPM, a node with no reference, an evidence document that cannot be read, a
binding that cannot be read, and own evidence that the appraisal refuses all state
`unattested` (A-2). The node still mints. Nodes without a TPM federate today, and refusing to
mint would turn an honest platform fact into an outage. `unattested` is a claim a relying
party can act on. A refusal to mint tells it nothing.

The claims are never omitted. `AssertionClaims::new` takes a `NodeAttestation`, not an
`Option`, and every field is serialized. An absent claim reads as an error to a rule that
tests `== 'attested'`, but it reads as a **pass** to a rule that tests `!= 'contested'`. So
the verifier refuses an assertion that lacks any of the four claims (`ClaimRefusal::Omitted`).

One case is a refusal, not a choice: on a TPM-custody node whose boot state moved, the TPM
will not sign at all, so nothing is minted. That is ADR 0012's binding doing its job.

### How stale `attested` can be

At the mint time `iat`, the node says `attested` only if the quote is at most `epoch + 30` s
old. The assertion lives `exp − iat ≤ MAX_TTL`. At any instant a relying party accepts the
assertion, `now < exp`, so the quote is at most `epoch + 30 + (exp − iat)` old: **630 s**
with the defaults (300 + 30 + 300), and 3930 s at the 3600 s TTL cap.

A relying party tightens this with `exp − nucleus_att_time ≤ max`. That needs no clock of its
own beyond the `exp` check it already makes, which matters because workload-identity
providers' conditions see the token, not the time. `RELYING_PARTY_CONDITION` uses 900. The
token the relying party then issues has its own lifetime. The bound holds at the exchange.

### The verifier

`nucleus_federation::verify_attestation_claims(claims, RelyingPartyCheck)` runs after the
caller has verified the signature, `iss`, `aud` and `exp` (for example with
`ExternalIssuerValidator`). It checks the following:

1. All four claims are present and well formed. `none` is all-or-nothing, and a tier other
   than `unattested` must name evidence.
2. The named quote is at most `max_age_secs` old at `now`, and is not more than 60 s in the
   future.
3. With `Reappraisal::Evidence`, the document hashes to the digest claim, it is the claimed
   epoch at the claimed time, and the relying party's own `appraise` at `iat` gives the
   claimed tier. A claim of `unattested` is never contradicted, because it is the node
   declining to vouch, which is never false.

`nucleus-audit` does not verify assertions, so it is unchanged. It remains the tool that
checks a JWKS is `TpmBound` before a relying party registers it.

### What the claim is worth

The claim is signed by the issuer key, so it is worth what that key is worth.

- **With a `TpmBound` key**, the claim means "a node in this measured boot state asserted
  this". A copied disk cannot sign it, and neither can the same disk booted differently.
- **With a file key**, anyone holding a copy can sign `attested`. A relying party must
  register only a JWKS that `verify-node-evidence --jwks --federation-key-attestation`
  passes.
- **Not the TPM's word.** The key binds the boot, not the userspace (IMA, PCR 10, is not in
  the key's policy). A replaced `nucleus-node` on an unchanged boot can sign, and can write
  `attested` over an old good epoch. It cannot make a fresh quote that hides the replacement.
  So a relying party that re-appraises the named evidence under an age bound catches the
  replacement within the bound. A stock provider's CEL condition does not re-appraise.

### Gatehouse's side (interface only)

The Gatehouse forge minter is a relying party that can re-appraise in full. On each exchange
it can do the following:

- Fetch `nucleus_evidence_digest` from the node's public evidence listener
  (`GET /v1/evidence/{sha256}`), or from its own cache.
- Call `verify_attestation_claims` with `Reappraisal::Evidence(HeldEvidence { document,
  binding, reference, anchors })`. The binding is the node's executor key, pinned at
  registration or read from `GET /v1/node/keys`, and the SHA-256 of the JWKS it registered.
- Refuse unless the result is `attested` both as claimed and as re-appraised.

Once per JWKS change, it can also require `appraise_federation_keys` to give `TpmBound` for
every key. The minter's queueing, caching and policy are Gatehouse's.

### Evidence for A3

The evidence is real: the epoch-4 document the #2706 live run's cloud vTPM produced, with the
AK pin the provider's API reported.

- **`nucleus-federation/tests/attestation.rs`:**
  - The node's statement:
    - An appraised node states `attested`, epoch 4, the quote time, and the digest the run's
      receipt named.
    - No TPM, no reference, no pin, a non-document, challenge evidence and evidence bound to
      another key all state `unattested`.
    - A diverging reference states `contested`.
    - Evidence older than `epoch + 30` s states `expired`.
    - All four claims are present, as strings, for every one of these.
  - The verifier:
    - It refuses a stale epoch (901 s against 900) and a quote from the future.
    - It refuses a tier the relying party's appraisal does not find: attested over a contested
      reference, attested without a pin, contested over attested evidence, and a forged
      `attested`.
    - It refuses other bytes than the named document, and the wrong epoch.
    - It refuses each omitted claim by name, a half-`none` epoch, and a tier naming nothing.
    - End to end: a signed assertion passes `ExternalIssuerValidator`, and its claim is then
      refused as stale.
  - The relying party's condition:
    - `RELYING_PARTY_CONDITION`, evaluated by `cel-interpreter` (the CEL implementation
      portcullis already locks, with JSON numbers as doubles as a provider presents them),
      admits a fresh `attested` assertion.
    - It refuses every other tier, an epoch 901 s old at `exp`, a quote time after `iat + 60`,
      and each claim it reads omitted.
    - The per-upstream recipe refuses another upstream's assertion.
- **`nucleus-node`:**
  - Every mint asks the platform anew: `unattested`/`none` before attach, `attested` from the
    fixture, then `unattested` from the same source, on consecutive assertions.
  - The flags are strict: a reference without a TPM, a pin without an operator anchor, and a
    malformed or unreadable input are each refused. Neither flag is read from the
    environment.
  - The docs quote the tested condition and recipe verbatim.

**A-19.** Each probe below injects one defect, the named tests turn red, and the probe is
restored byte for byte (checked by digest):

| probe | red |
|---|---|
| no reference states `attested` | cannot-vouch; CEL condition; tier-mismatch |
| own evidence refused states `attested` | cannot-vouch |
| node max age unbounded (an old tier carried forward) | older-than-one-epoch is expired; CEL condition |
| verifier skips the age check | stale epoch; end to end |
| verifier accepts any tier over the evidence | tier-mismatch |
| verifier reads an omitted claim as `none` | omitted claim refused |
| an empty claim skipped on the wire (`skip_serializing_if`) | never omitted; omitted claim refused; host-observed claims; node per-mint |
| condition tests `!= 'contested'` instead of `== 'attested'` | CEL condition; per-upstream recipe; docs quote the condition |
| issuer keeps the first mint's tier | node per-mint |

**Live vTPM run (2026-10-07).**

- **Setup:** one Spot n2 Shielded VM in us-east1-b (Ubuntu 24.04, kernel 7.0, Secure Boot on),
  created and deleted under the automation identity. It ran
  `nucleus-federation/examples/attested_assertion`, built x86_64 musl from this change. The
  example takes the node's steps: an epoch quote bound to the issuer JWKS digest, then
  `of_current_evidence` against the exact boot reference of the #2706 run and the AK pin the
  provider's API reported (`d0f0d1c2…b7f2`, equal to the quoted AK). It then mints, evaluates
  the CEL condition, and runs the verifier with re-appraisal.
- **Before:**
  - The TPM key minted `attested`, epoch 1. The condition admitted it, and the verifier
    re-appraised `attested`.
  - The file key (waived custody) gave the same result.
- **After `tpm2_pcrextend 8`:**
  - The TPM key refused to sign, so nothing was minted.
  - The file key minted `unattested`, naming epoch 2. The node's own appraisal was refused
    because the boot event log does not replay to PCR 8. The condition refused the assertion,
    and so did the verifier, which named the same refusal.

### What A3 does not do

- **No live WIF provider test.** A live test against a real provider would need a new IAM
  resource, which is an owner decision. The provider recipe is in the runbook (§2a). The
  condition is tested offline with a CEL implementation, not against the provider's own
  evaluator. The two differ in error handling: `cel-interpreter` short-circuits `&&` left to
  right, while CEL proper is commutative over errors. Both refuse every case tested, because
  a condition must be exactly `true`.
- **The node's self-appraisal takes operator pins only, not certificate-chain trust roots.**
  A node whose AK is anchored by a certificate chain states `unattested` until a
  `--node-evidence-trust-root` flag exists.
- **The live run used the example, not a node serving a pod.** The node's wiring (attach,
  per-mint ask) is covered by the `nucleus-node` tests above.

## References

- TPM 2.0 Library, Part 1 (Names, qualified Names, policy sessions), Part 2
  (`TPMA_OBJECT`, `TPMS_CERTIFY_INFO`), Part 3 (`TPM2_PolicyPCR` 23.7, `TPM2_Certify`,
  `TPM2_Create`, `TPM2_Load`, `TPM2_Sign`).
- TCG PC Client Platform Firmware Profile (the PCR allocation), and the TCG provisioning
  guidance's SRK template.
- systemd-measure(1), systemd-cryptenroll(1) `--tpm2-public-key`: signed `PolicyAuthorize`
  policies over predicted PCR 11.
- RFC 9334 (RATS), RFC 9711 (EAT).
