# Spike: attested nodes on one cloud's Arm machines (measure only)

**Status:** Measurement report for issue #2706 (L-5, attestation). No product code
changed. **Date:** 2026-10-05, 22:52–23:04 UTC. **Environment:** one operator's Google
Cloud project, region `us-east4` (one probe in `us-central1`), `gcloud` 587.0.0,
Ubuntu 24.04 LTS images, go-tpm-tools `gotpm` v0.4.10 (release tarball, checksum
verified). Following the precedent of `microvm-host-apple-container.md`, the provider is
named here because the facts are about its machines; nothing in the product depends on
it.

**Verdict for Arm on this provider: NO-GO today.** No Arm VM shape exposes KVM, and no
non-confidential VM can obtain the provider-signed attestation token. The one Arm shape
that could host Firecracker (C4A bare metal) was blocked by project quota and is
untested. A different evidence shape — a vTPM quote plus event logs, verified by
nucleus itself — works on Arm today and is the recommended direction (see
[Recommended shape](#recommended-shape)).

## The question

Can one Arm machine both (a) run nucleus's Firecracker pods, which need `/dev/kvm`, and
(b) obtain a provider-signed attestation token that binds the node's public key, so a
receipt can carry third-party-verifiable evidence of what booted?

## Results

| Probe | Result | One line |
|---|---|---|
| P1 C4A VM, nested virt | **FAIL** (KVM) / PASS (Shielded) | Flag accepted and stored; guest runs at EL1, no `/dev/kvm`. vTPM + Secure Boot work. |
| P2 C4A metal | **NOT RUN** | No Spot; on-demand blocked by C4A per-region vCPU quota (24 / 50 < 96). |
| P3 token with key binding | **FAIL** on Shielded (Arm and x86); **PASS** on a Confidential VM (x86, no KVM) | Shielded VMs have no AK certificate, so no token. A local quote binding the key verifies. |
| P4 measurement meaningfulness | **PARTIAL** | The token carries **no** measurements. The quote (all 24 PCRs) + event log identifies the kernel image, cmdline and, with IMA, each userspace binary. |
| P5 x86 control | KVM **PASS** / token **FAIL** | n2 with nested virt has KVM (API 12) but, being Shielded-only, gets no token either. |

No machine in this project has both KVM and the provider-signed token: the token needs
a Confidential VM, and a Confidential VM has no virtualization extensions.

## P1 — C4A VM with nested virtualization

```text
gcloud compute instances create attest-spike-c4a-nv --zone=us-east4-c \
  --machine-type=c4a-standard-1 --provisioning-model=SPOT \
  --instance-termination-action=DELETE --max-run-duration=3h \
  --image-family=ubuntu-2404-lts-arm64 --image-project=ubuntu-os-cloud \
  --boot-disk-type=hyperdisk-balanced --boot-disk-size=20GB \
  --enable-nested-virtualization \
  --shielded-vtpm --shielded-integrity-monitoring --shielded-secure-boot \
  --labels=purpose=nucleus-attest-spike
```

- The API **accepted** the request (18.7 s) and stored
  `advancedMachineFeatures.enableNestedVirtualization: true`, `cpuPlatform: Google Axion`.
  Accepted is not honoured:
- Guest kernel `7.0.0-1011-gcp` aarch64: `CPU: All CPU(s) started at EL1`,
  `kvm [1]: HYP mode not available`, no `/dev/kvm` (`CONFIG_KVM=y` in the kernel, so the
  absence is the platform, not the build). `KVM_GET_API_VERSION` is unreachable.
- Shielded options all work on C4A: `/dev/tpm0`, `/dev/tpmrm0` present, `mokutil` reports
  `SecureBoot enabled`, `/sys/kernel/security/tpm0/binary_bios_measurements` present.
  vTPM manufacturer `GOOG`, vendor string `vTPM`.
- Same result on the other Arm series: `t2a-standard-1` (Ampere Altra, `us-central1-a`)
  with the same flags — flag stored, `started at EL1`, `HYP mode not available`, no
  `/dev/kvm`.

**Silent acceptance is the trap here.** A provisioning path that sets the flag and checks
the API response would believe it has a KVM-capable node. The only reliable check is
on the guest: `/dev/kvm` exists and `KVM_GET_API_VERSION` returns 12.

## P2 — C4A bare metal

- `c4a-highmem-96-metal` (96 vCPU, 768 GB) is listed in `us-central1-{a,b,c}`,
  `us-east4-c`, `asia-northeast1-{a,b}`. It is the only metal C4A shape; there is no
  smaller one.
- Spot: refused — `C4A Highmem Bare Metal does not support preemptible instances.`
- On-demand also requires `--maintenance-policy=TERMINATE`
  (`onHostMaintenance must be set to TERMINATE for machine type - c4a-highmem-96-metal`).
- With that, refused by quota: `Quota 'CPUS_PER_VM_FAMILY' exceeded. Limit: 24.0 in
  region us-east4` (`vm_family: C4A`), and `Limit: 50.0 in region us-central1`. Raising
  it is an owner action; the spike did not request it.
- Price (billing catalog, `us-east4`, on-demand): C4A core US$0.03086/h, RAM
  US$0.00351/GiB·h ⇒ 96 × 0.03086 + 768 × 0.00351 ≈ **US$5.66/h** before disk. (Spot
  rates exist for the family — US$0.01838/core·h, US$0.002091/GiB·h — but metal cannot use
  them.) One hour fits this spike's budget; quota, not price, stopped it.
- The provider's bare-metal documentation states vTPM features are unavailable on bare
  metal "with the exception of A4X Max and C4A bare metal", and that nested
  virtualization is not supported on metal (which is moot — a metal host runs KVM
  directly at EL2). **Not measured:** whether `/dev/kvm` appears, whether Firecracker
  v1.17.0 aarch64 boots the pinned `vmlinux-6.1.141` guest, and — the decisive question —
  whether its vTPM carries an AK certificate (see P3: without one, no token).

## P3 — attestation token binding the node key

Key binding as specified: an ephemeral P-256 key, `eat_nonce = hex(sha256(SPKI DER))`
(64 bytes, inside the 10–74-byte limit).

```text
openssl ecparam -name prime256v1 -genkey -noout -out node.key
openssl ec -in node.key -pubout -outform DER -out node.pub.der
N=$(sha256sum node.pub.der | cut -d' ' -f1)
sudo gotpm token --custom-nonce "$N" --audience nucleus-attest-spike --output token.jwt
```

Setup this needed: enable `confidentialcomputing.googleapis.com` in the project; a
dedicated service account with `roles/confidentialcomputing.workloadUser` and the
`cloud-platform` scope on the VM (the default compute scopes cannot call the API).

**C4A Shielded VM — FAIL, 0.33 s, before any network call:**

```text
Error: failed to find GCE AK Certificate on this VM: try creating a new VM or verifying
the VM has an EK cert using get-shielded-identity gcloud command. The used key algorithm is: RSA
```

`--algo ecc` gives the same error. The vTPM's NV indices explain it: only the AK
*templates* are present (`0x01c10001` RSA, `0x01c10003` ECC); the AK *certificate*
indices `0x01c10000`/`0x01c10002` and the EK certificate indices `0x01c00002`/`0x01c0000a`
return `TPM_RC_HANDLE`. `gotpm` refuses client-side, and the verifier API's TPM
attestation message has no field for an uncertified AK — it takes `ak_cert` plus a chain.

**x86 Shielded VM (P5 control, n2-standard-2, nested virt) — the same error.** So this
is not an Arm gap: Shielded-only VMs in this project receive no AK certificate.

**x86 Confidential VM (n2d-standard-2, `--confidential-compute-type=SEV`) — PASS, 1.08 s.**
The VM was created *with* `--enable-nested-virtualization`; the API accepted and stored
it, but the guest has no `svm`/`vmx` flag and no `/dev/kvm` (the documented
"Confidential VMs do not support nested virtualization", confirmed, and again silently).

Verified outside the VM (`verify_token.py`, ~30 lines over `cryptography`): RS256
signature against the JWKS named by the issuer's discovery document
(`https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com`),
`nbf ≤ now < exp`, `aud`, and `eat_nonce == hex(sha256(pubkey DER))`. Flipping one bit of
the public key makes the nonce check fail. Claims, with per-instance identifiers
redacted:

```json
{
 "aud": "nucleus-attest-spike",
 "eat_nonce": "1f944be4ff8e59924858db416abffc0b418bd5518081aa7733e5d97291d193de",
 "eat_profile": "https://cloud.google.com/confidential-computing/confidential-vm/docs/token-claims",
 "exp": 1791244817, "iat": 1791241217, "nbf": 1791241217,
 "google_service_accounts": "<redacted>",
 "hwmodel": "GCP_AMD_SEV",
 "iss": "https://confidentialcomputing.googleapis.com",
 "oemid": 11129,
 "secboot": true,
 "sub": "<redacted>",
 "submods": { "gce": { "instance_id": "<redacted>", "instance_name": "<redacted>",
                       "project_id": "<redacted>", "project_number": "<redacted>",
                       "zone": "us-east4-c" } },
 "swname": "GCE"
}
```

Token lifetime 3600 s; JWT 1462 bytes. A single string nonce is echoed as a string, not
an array — a verifier must accept both.

`hwmodel: GCP_SHIELDED_VM` was never observed: in this project there is no VM shape
that is Shielded-only *and* has an AK certificate.

### What does work on the C4A Shielded VM: a local quote over the same nonce

```text
sudo gotpm attest --key gceAK --algo ecc --nonce $N --format textproto --output att.txtpb
```

The attestation carries `ak_pub`, three quotes (SHA1/SHA256/SHA384 banks, each over PCRs
0–23), the TCG event log and `instance_info` — but no `ak_cert`. Verified on a
*different* VM with `gotpm verify debug --nonce $N`: quote signatures and event-log
replay pass; the same file with a wrong nonce fails
(`quote extraData [...] did not match expected extraData [...]`).

The AK is anchored only by the provider's Compute API: `ak_pub`'s P-256 point equals the
`eccP256SigningKey.ekPub` that `gcloud compute instances get-shielded-identity` returns
for that instance. That anchor is an authenticated API response that requires
`compute.instances.getShieldedInstanceIdentity` on the project — not a signed artifact a
third party can check offline. The shielded identity output was captured only in part
(EK/AK public keys); whether it also carried an `ekCert` was not recorded.

## P4 — what the measurements identify

**The provider token identifies nothing that booted.** Its measurement-like claims are
`secboot` (a boolean), `swname: "GCE"` and `hwmodel`. No PCR, no kernel digest, no
cmdline. For this question it attests "a Confidential VM in this project with Secure
Boot on", not "this kernel and this node binary".

**The quote + event log does identify the boot chain.** `gotpm verify debug` on the C4A
quote yields a verified machine state with: Secure Boot state and the full `db`, `dbx`,
`PK`, `KEK` contents (PCR7); three EFI application digests (PCR4 — consistent with
shim → GRUB → kernel; not individually matched against the files in this spike); and,
as raw events, the GRUB commands and `kernel_cmdline: /vmlinuz-7.0.0-1011-gcp
root=PARTUUID=… ro console=ttyS0,115200 panic=-1` (PCR8) and the files GRUB loaded
(PCR9). `gotpm` does not parse PCR10.

**Userspace via IMA (PCR10).** Rebooted the C4A VM with
`ima_policy=tcb ima_hash=sha256 ima_template=ima-ng` on the cmdline (2051 measurements
at first login). The IMA log contains the `gotpm` binary with its file hash:

```text
10 1272c586… ima-ng sha256:98dcbf249204d9d4de61f314977475deaebf493cc76da129687eb9fb76e5ee1c /usr/local/bin/gotpm
```

which equals `sha256sum /usr/local/bin/gotpm`. A fresh quote (verified as above) was
taken, then the binary IMA log copied; replaying the log into a SHA-256 PCR10
(`ima_replay.py`) reproduces the quoted PCR10
`a4cde48c4cc79362c5c938bc33cde416fa480e544333f3379efc8e39a5682f2f` at entry 2308 of 2310
(the log grew by two entries between quote and copy — a verifier must accept a matching
prefix). So a quote can prove that a named binary with a given hash was executed on
the quoted machine.

**Not covered / not measured:**
- dm-verity root hash on the cmdline: not tried. It would land in PCR8 via GRUB's
  `kernel_cmdline` event, as the cmdline above did, so it is reachable by the same
  replay — untested.
- `tcb` IMA measures everything executed and every root-read file (2000+ entries at
  boot); a production policy should measure a named set (node binary, Firecracker,
  jailer, guest kernel, rootfs image).
- IMA measures a load; it does not prove the binary is still the one running.
  Appraisal/enforcement is not tested.
- What runs *inside* a Firecracker guest is not measured by the host TPM at all; that is
  the per-pod half of #2706 and is out of scope here.

## P5 — x86 control

`n2-standard-2` Spot, `--enable-nested-virtualization --min-cpu-platform="Intel Cascade
Lake"`, Shielded vTPM/Secure Boot: `/dev/kvm` present (`crw-rw---- root kvm`),
`KVM_GET_API_VERSION` = **12**. Token: **FAIL**, the same missing-AK-certificate error as
C4A. The x86 path gives KVM but not the provider token, so it is not a fallback for the
token; it is a fallback only for the quote-based shape, exactly as Arm metal would be.

## Recommended shape

1. **Do not depend on the provider token.** On this provider it requires a Confidential
   VM, which cannot run KVM, and even where issued it carries no boot measurements.
2. **Node evidence = a TPM quote, not a cloud token**: quote over all PCRs with
   `qualifying data = sha256(node public key SPKI DER)`, plus the TCG event log and an
   IMA log restricted to a named policy. The verifier replays both logs and checks named
   digests (kernel, cmdline incl. a dm-verity root hash, node binary, Firecracker). This
   is provider-neutral, works on both Arm and x86 vTPMs measured here, and fits the
   receipt format as an evidence blob verified by `nucleus` itself.
3. **The AK endorsement is the pluggable, trust-bearing part**, and should be a named
   variant, never implied: (a) a certificate chain to a provider CA where one is
   provisioned; (b) a hardware TPM EK certificate on bare metal; (c) an operator-asserted
   AK fetched from a provider API — which is operator-vouched, not third-party
   verifiable, and must be labelled so in the receipt.
4. **Probe the platform, not the API response**: a node must check `/dev/kvm` +
   `KVM_GET_API_VERSION` on itself; both the nested-virt flag on Arm and on a
   Confidential VM were accepted, stored and not honoured.

## Open, cheapest next step

One hour on `c4a-highmem-96-metal` (≈ US$5.66 + disk) after the owner raises the C4A
per-region vCPU quota to ≥ 96 in `us-east4` or `us-central1`. It answers three questions
in one boot: `/dev/kvm` + Firecracker v1.17.0 booting the pinned guest; whether its vTPM
has an AK certificate (`gotpm token` either succeeds or fails exactly as above); and the
`hwmodel` it would report.

## Cost and teardown

All instances were labelled `purpose=nucleus-attest-spike` and Spot with
`--instance-termination-action=DELETE` and a `--max-run-duration` cap: two
`c4a-standard-1` (≈ 2 and 10 min), one `n2-standard-2` (≈ 8 min), one SEV
`n2d-standard-2` (≈ 6 min), one `t2a-standard-1` (≈ 2 min). The metal instance was never
created. Estimated compute spend from catalog rates: **under US$0.10**. A teardown
script deleted every instance matching both the label and the `attest-spike-` name
prefix, removed the spike service account's two IAM bindings and deleted the account.
`gcloud compute instances list --filter=labels.purpose=nucleus-attest-spike` returned
0 items afterwards. The `confidentialcomputing.googleapis.com` API remains enabled; it
has no standing cost. No token, key or attestation file is committed.
