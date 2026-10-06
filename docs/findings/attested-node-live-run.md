# Live run: a receipt from a TPM-attested node, verified off the box (#2706 PR-3)

**Status:** measured 2026-10-06, 00:21–00:46 UTC. Code: the #2706 PR-2 branch
(`87aa30892`). Following the precedent of `attested-node-gcp-spike.md`, the cloud
provider is named because the facts are about its machines. Nothing in the product
depends on that provider.

**Verdict.** The stranger's check (North Star, "Position: verifiable authority")
works for the node. A Firecracker pod ran on a node that attests its own boot.
Its signed execution receipt named the node's TPM evidence. On a different machine
and a different CPU architecture, `nucleus-audit verify-execution --require-attested`
returned `authorized_on_an_attested_node` with anchor `OperatorFetched`. Replays came
out `Expired`. A reboot with a changed command line came out `Contested`, with both
changes named.

## Setup

| | |
|---|---|
| Node VM | x86_64 `n2-standard-16` Spot, nested virtualization, Shielded VM (vTPM, Secure Boot, integrity monitoring). Ubuntu 24.04, kernel `7.0.0-1011-gcp`. `/dev/kvm` and `/dev/tpmrm0` present. |
| Build | `cargo build --release --target x86_64-unknown-linux-musl` of the branch on the node VM; guest rootfs from `scripts/firecracker/build-rootfs.sh`; `nucleus setup --artifacts local` (the `quickstart-boot` recipe). |
| Node flags | `NUCLEUS_NODE_EVIDENCE_TPM=/dev/tpmrm0`, `…_AK_TEMPLATE=nv:0x01c10003` (the provider's ECC AK template), `…_ANCHOR=operator:gcp-shielded-vm-identity:attest-live-x86`, `…_EPOCH_SECS=120`, `NUCLEUS_NODE_BROKER_ENFORCING=true`. |
| Narrow IMA | `nucleus-node`, `firecracker` and `jailer` moved to a dedicated ext4 at `/opt/nucleus`, symlinked back. Policy: `measure func=BPRM_CHECK fsuuid=U` + `measure func=FILE_CHECK mask=MAY_READ fsuuid=U`. The log held 67 entries: `boot_aggregate`, the kernel modules the platform's Secure Boot policy measures, and the three node binaries. |
| Verifier | `nucleus-audit` built natively on a **different** VM (aarch64 builder) from the same commit. It received only files: receipt, admission, evidence documents, reference manifest. |
| AK pin | SHA-256 of the SPKI of `eccP256SigningKey` returned by `gcloud compute instances get-shielded-identity`, computed on a laptop with `openssl pkey -pubin -outform DER \| shasum -a 256`: `beced817…2366`. It equals the AK in every quote. |

The reference manifest came from `cargo xtask node-reference-manifest`, using
`sha256sum` listings made **on files**, never from the logs:

- the nine files GRUB loads from `/boot`;
- every `.ko*` under `/usr/lib/modules/7.0.0-1011-gcp` (6,858 files);
- the three installed node binaries. The installed `nucleus-node` digest (`88859daf…`) equals the build output's.

The command line was pinned with the GRUB-measured parameters. EFI application
(Authenticode) digests were `not_checked`, and the appraisal says so.

## Results

| Step | Input | Result |
|---|---|---|
| Node start | TPM attester, first epoch quote | node serves only after epoch 1 is stored; restart resumed at epoch 3 (counter persisted) |
| `nucleus verify --tier2 --here` | real pod on this node | pass (identity, admission gate, probes, seccomp) |
| Pod `370841ff…` (pinned kernel/rootfs/scratch, `/bin/sh` workload, exit 0) | `workload collect` | receipt `node_platform = {evidence: {evidence_sha256: d0689ce4…, epoch: 4}}` |
| `GET /v1/node/evidence/d0689ce4…` | the document the receipt names | bytes hash to `d0689ce4…` |
| **Off-box `verify-execution --require-attested`** | receipt + epoch-4 evidence + reference + pin | **exit 0, `authorized_on_an_attested_node`, tier `attested`, anchor `operator_fetched`** |
| Same, no `--operator-pin` | | exit 0, `authorized_platform_not_attested`, `unattested (no_matching_operator_pin)` |
| Receipt with `exit_code` edited | | refused (root hash mismatch) |
| Challenge quote over a fresh nonce | `verify-node-evidence --nonce <sent>` | `affirming` |
| **Same challenge evidence, replayed** to a verifier that sent another nonce | | **`expired (nonce_mismatch)`**, exit 1 |
| **Epoch-4 evidence replayed** against a receipt one hour later (max age 900 s) | | **`expired (too_old 3600/900)`**, exit 1 |
| **Reboot with `nucleus.perturbed=1` appended** (`/etc/default/grub.d`, `update-grub`), challenge quote | reference with exact command line | **`contested`**: `kernel_cmdline` (observed line shown) **and** `boot_file_not_allowed (grub/grub.cfg)` |
| Same, reference with `required_params` only | | `contested`, but **only** the grub.cfg divergence. See finding 1. |

The epoch-4 document and the perturbed challenge document are checked in as test
fixtures (`crates/nucleus-node-evidence/tests/live_node_fixtures.rs`). The test
asserts that the first one's bytes hash to the digest the live receipt named.

## Findings

1. **`required_params` cannot see an added parameter.** The appended
   `nucleus.perturbed=1` satisfied it. The run was still `Contested`, but only
   because `update-grub` rewrote `grub.cfg` (PCR 9). A command line changed at the
   GRUB prompt, without rewriting `grub.cfg`, would have passed. **Fixed in this PR**
   with a new rule `CmdlineRule::ExactParams` (word set equality, any order) and
   `xtask node-reference-manifest --cmdline-exact-params`. `RequiredParams` is now
   documented as weaker. A-19: neutralising the set comparison turns
   `a_reboot_with_an_added_parameter_is_contested_and_both_changes_are_named` red.
2. **GRUB measures a different command line than `/proc/cmdline` shows.** GRUB
   measures `/vmlinuz-… root=…`; the kernel shows `BOOT_IMAGE=/vmlinuz-… root=…`.
   A reference copied from `/proc/cmdline` would contest every honest boot. The
   reference must use the GRUB form; the `ExactParams` doc comment says so.
3. **The "public" evidence routes are behind the node's mTLS handshake.** The
   listener requires a client certificate before any route runs, so
   `GET /v1/node/evidence/{digest}` needs one. Today a stranger gets evidence from
   the operator, alongside the receipt, as in this run. Serving it to anonymous
   relying parties needs a server-auth-only listener (as `federation_ingress` has).
   Not changed here.
   *Since:* `nucleus-node --public-evidence-addr` serves
   `GET /v1/evidence/{sha256}` on such a listener (no client certificate, no
   challenge route). Not yet exercised on a live attested node.
4. **Host spec enforcement must be on.** Without `NUCLEUS_NODE_BROKER_ENFORCING=true`,
   the guest ran the rootfs's baked spec, and the receipt was correctly refused for
   lacking a program identity (#3205).
5. **Expectations must name every resolved environment input** (`HOME`, `PATH`,
   `LANG`, `TZ`). A receipt for a spec that set only `PATH` failed
   `environment_inputs_sha256` against expectations that named only `PATH`. That
   refusal is correct; the work is in writing expectations completely.

## What a stranger can now verify, and what not

- **Can verify, offline.** The key that signed this receipt belongs to a node whose
  boot replays to TPM-quoted PCRs, specifically:
  - Secure Boot was on;
  - the GRUB-loaded kernel is the one hashed from `/boot`;
  - the measured command line is exactly the expected one;
  - `nucleus-node`, `firecracker` and `jailer` were loaded with the expected digests, and nothing else was measured on the node's install filesystem;
  - the evidence is fresh relative to the receipt.

  This requires accepting one input: the operator's statement that this AK is the vTPM's.
- **Tier.** `Attested`, with anchor `OperatorFetched`, the weakest anchor. The AK
  is vouched for by the provider's authenticated API, as reported by the operator.
  Nothing a stranger can check cryptographically ties it to hardware. The spike
  found no provider-issued AK certificate on any VM shape that can run KVM.
- **Not covered.**
  - What runs inside the guest: the host TPM does not measure it.
  - Whether the measured binaries are still what is running (IMA records loads).
  - The node's clock (epoch `iat`).

## What remains

- A hardware- or CA-anchored AK (`CertificateChain`): Arm bare metal, or an EK/AK
  certificate. Blocked on quota for the one candidate shape (spike, P2).
- The wasm verifier for `sdks/verifier-js` (and Python). The crate is pure Rust and
  not yet embedded. *Since done: ADR 0011, "As built: the stranger's verifiers"; the
  epoch-4 and perturbed documents above are two of its parity cases.*
- Reference manifests published with releases, including Authenticode digests for PCR 4.
- ~~An anonymous, server-auth-only route for evidence (finding 3)~~ (since:
  `--public-evidence-addr`), and binding the digest into the admission record.

## Cost and teardown

Two Spot VMs, both labelled `purpose=nucleus-attest`:

- `n2-standard-2` for the PR-1 fixtures, about 10 minutes;
- `n2-standard-16` for this run, about 25 minutes.

Estimated compute below US$0.30. Both instances were deleted. Afterwards,
`gcloud compute instances list --filter=labels.purpose=nucleus-attest` returned
nothing. No key or token is committed. The fixtures hold public keys, quotes and
logs only.
