# Verifying a receipt as a stranger

This guide is for someone who holds **no operator credentials** and wants to check a
Nucleus execution receipt: that a policy allowed the work, and that the node which signed
the receipt booted the software it should have. It follows the North Star position
("Position: verifiable authority") and ADR 0011.

You need four things. None of them come from trusting the node:

| Input | Where it comes from | Who vouches for it |
|---|---|---|
| The **receipt** and the **expectations** it is checked against | The operator, or whoever handed you the work | The receipt's signature; the expectations are yours |
| The **node evidence** document the receipt names | The operator, or the node's public evidence listener | Its SHA-256 equals the digest the signed receipt names |
| The **reference manifest** | The release's assets | The release workflow's Sigstore signature, logged in public |
| The **AK pin** | The operator, from the platform's authenticated API | The operator. This is the weakest input; see below |

For worked examples, see [Release-journey evidence](evidence/README.md). It covers one `Attested`
run on v2.6.0 and two `Unattested` runs on v2.5.0, each with the commands to re-check it
against the published release assets.

## 1. Fetch and check the release's reference manifest

Each release from this one on publishes, per architecture:

- `nucleus-<version>-<arch>.node-reference.json`, the reference manifest
  (`nucleus-node-reference/v1`), and
- `nucleus-<version>-<arch>.node-reference.json.sigstore.json`, its keyless Sigstore
  signature bundle.

`cargo xtask release-reference-manifest emit` writes the manifest in the release workflow.
It hashes the bytes the release ships, never an event log:

- `nucleus-node` comes from the musl tarball that `nucleus setup` installs.
- `firecracker` and `jailer` come from the upstream Firecracker release archive, at the
  version the node pins (`nucleus_spec::vmm_version::PINNED`).

```sh
VERSION=vX.Y.Z
ARCH=x86_64   # or aarch64
gh release download "$VERSION" --repo coproduct-opensource/nucleus \
  --pattern "nucleus-${VERSION#v}-${ARCH}.node-reference.json*"

cosign verify-blob \
  --bundle "nucleus-${VERSION#v}-${ARCH}.node-reference.json.sigstore.json" \
  --certificate-identity "https://github.com/coproduct-opensource/nucleus/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "nucleus-${VERSION#v}-${ARCH}.node-reference.json"
```

`cosign verify-blob` checks three things:

- the signature over the manifest's bytes;
- that the signing certificate was issued to this repository's release workflow at this
  tag;
- the **inclusion proof** of that signature in the public Sigstore transparency log
  (Rekor), which the bundle carries.

A release cannot quietly publish one set of reference values to one verifier and another
set to the next, because every published value is in an append-only public log. That is
the pattern arXiv 2409.03720 (*Confidential Computing Transparency*) argues for: publish
the reference measurements to a transparency log, so that a relying party need not trust
the publisher's distribution channel.

To check the manifest itself, download the release's
`nucleus-node-<version>-<arch>-unknown-linux-musl.tar.gz` and upstream Firecracker's
`firecracker-v<pin>-<arch>.tgz`, then compare `sha256sum` of the extracted binaries with
the manifest's allowlist.

### What a release manifest checks, and what it does not

The release publishes **no host image**. The node runs on an image that the operator
chose. So the release manifest checks only the node's own files:

- **IMA allowlist.** `nucleus-node` is required. `firecracker` and `jailer` are allowed
  but not required: IMA measures a binary when it runs, and a node quoted before its
  first pod has not run either. A replaced binary that did run appears with a digest that
  is not allowed, and the evidence is `Contested`.
- **IMA scope.** The allowlist governs the install directory only:
  `"scope": {"path_prefixes": ["/usr/local/bin"]}`. A host's own IMA policy measures more
  than the node's files. A Secure Boot host's policy measures every kernel module it
  loads, for example, and the release vouches for none of them. A measured file outside
  the scope is neither allowed nor divergent. The appraisal lists it under
  `ima_not_in_scope`, with its path and digest, beside the verdict. Inside the scope
  nothing is forgiven: an unlisted or replaced binary under `/usr/local/bin` is
  `Contested`. The scope is part of the signed manifest, so evidence can neither set
  nor widen it. A prefix matches whole path components, so `/usr/local/bin` does not
  cover `/usr/local/binx/…`. A required path outside the scope, or a malformed prefix,
  makes the IMA check `not_evaluable`, never a pass. A manifest without a `scope`
  (every release up to and including v2.5.0) governs every measured file.
- **Everything else** (Secure Boot state, EFI applications, boot files, kernel command
  line, PCR pins) is `not_checked`, with the reason written into the manifest. The
  appraisal prints every `not_checked` item beside its verdict. An `Attested` result
  against the release manifest alone therefore says nothing about the host's boot, and
  says so.
- **Install paths.** The paths are where `nucleus setup` installs (`/usr/local/bin`). IMA
  records the path after symlinks resolve. A node that keeps its binaries on a dedicated
  filesystem (the narrow-IMA layout in `docs/findings/attested-node-live-run.md`)
  regenerates the manifest with `--install-dir` from the same signed tarballs. The
  digests do not change; only the paths and the scope do.

**What a release-only appraisal yields.** This was measured on the attested journey re-run
(2026-10-06): release v2.5.0 on an x86 Shielded VM with Secure Boot, with the node's
binaries on a read-only filesystem mounted at `/usr/local/bin`. The quoted IMA log held
`boot_aggregate`, the three node binaries and 64 kernel modules measured by the platform's
Secure Boot policy.

- Against the published v2.5.0 manifest, which has no scope, the verdict is `Contested`,
  with 64 `ima_file_not_allowed` divergences, one per kernel module.
- Against the same manifest with the install-directory scope that releases after v2.5.0
  publish, the verdict is `Attested`, with anchor `operator_fetched`.
  - All three binaries matched.
  - The four boot items are listed as `not_checked`, with the release's reason.
  - The 64 modules are listed under `ima_not_in_scope`.
- The same scoped manifest with any in-scope binary removed from its allowlist is
  `Contested`.

So a release-only `Attested` means three things: the node's own binaries are the
release's, the AK is the one the operator pinned, and the quote is fresh. It says nothing
about the host's boot or its kernel modules. The result names what it did not check
(`not_checked`) and what it did not judge (`ima_not_in_scope`). With a v2.5.0 manifest,
use the operator's reference values below, or regenerate the manifest from the same signed
tarballs with this repository's `cargo xtask release-reference-manifest emit`.

To check the boot as well, you need the operator's boot reference values. The operator
builds them from files, never from logs, and folds the release's allowlist in verbatim:

```sh
cargo xtask node-reference-manifest --tag-id my-node \
  --secure-boot required \
  --boot-file-sums boot-files.sha256 --boot-required-path /vmlinuz-<kernel> \
  --cmdline-exact-params '/vmlinuz-<kernel>' --cmdline-exact-params 'root=…' \
  --ima-sums platform-modules.sha256 \
  --ima-from-manifest nucleus-<version>-<arch>.node-reference.json \
  > node-reference.json
```

`jq '."reference-values".ima.required.allowlist'` on both files shows whether the
release's entries are present unchanged. The boot pins in that file are the operator's
statement, in the same way the AK pin is. The folded manifest does not inherit the
release's scope. Without `--ima-scope-prefix`, it governs every measured file, which is
why it must list the platform's modules.

## 2. Fetch the node evidence the receipt names

A signed execution receipt records
`node_platform = {evidence: {evidence_sha256, epoch}}`, or `unattested {reason}`. A receipt
that says `unattested` is never upgraded by evidence supplied beside it.

The evidence document is not secret. You can get it in either of two ways:

- **From the operator**, next to the receipt. That is how the live run in
  `docs/findings/attested-node-live-run.md` did it.
- **From the node itself**, through the public evidence listener. That listener is opt-in
  (`--public-evidence-addr`). It is server-authenticated only, so it asks for no client
  certificate, and it serves content-addressed documents:
  `GET /v1/evidence/<sha256>`. It is being added in a separate change. Until that change
  has landed and the operator has enabled the listener, the node's evidence routes sit
  behind its mTLS handshake.

Whichever way you get it, the document is content-addressed. Check that
`sha256sum evidence.json` equals the `evidence_sha256` the receipt names; the verifier
checks this too. A document fetched from an untrusted mirror is as good as one fetched
from the node.

## 3. Get the AK pin, and know what it is worth

The evidence is signed by the node TPM's attestation key (AK). On the KVM-capable cloud
VMs measured so far, nothing a stranger can check cryptographically ties that AK to
hardware. No AK certificate is issued; only the platform's authenticated API reports the
AK's public key, and only to the operator. So the pin is
`SOURCE=SPKI_SHA256`, as the operator reports it. The anchor is `OperatorFetched`,
labelled as such in every result. Without a pin, the platform tier is `Unattested`.
A hardware-anchored AK (`CertificateChain`) needs no operator trust; see ADR 0011,
"Limits".

**A software TPM is not a hardware root, and the verifier will not take it as one.**
Evidence whose anchor claim is `software_tpm` (swtpm, as nucleus's own CI live boot
runs) is anchored only by `--allow-software-tpm-pin 'SOURCE=SPKI_SHA256'`, and every
result labels it `software_tpm`. An `--operator-pin` never anchors it, and a
software-TPM pin never anchors an operator claim, so the commands below, which pass
only `--operator-pin`, return `Unattested` for a software TPM and
`--require-attested` fails. Whoever runs a software TPM can sign any quote with its AK:
pass that flag only for a node whose operator you are, or whose software TPM you
accept for testing.

## 4. Run the verifier

With the audit CLI, `nucleus-audit` from the release's `nucleus-audit-*` tarball, which
is signed in the same way as the manifest:

```sh
# The receipt, with the platform as a second axis:
nucleus-audit verify-execution \
  --receipt receipt.json --expectations expectations.json \
  --node-evidence evidence.json --node-reference node-reference.json \
  --operator-pin 'SOURCE=<spki-sha256>' \
  --require-attested

# Or the evidence alone, against a challenge nonce you sent:
nucleus-audit verify-node-evidence \
  --evidence evidence.json --reference node-reference.json \
  --executor-ed25519 <executor public key hex> \
  --nonce <the nonce you sent> \
  --operator-pin 'SOURCE=<spki-sha256>' \
  --federation <jwks-sha256>   # only for a node that federates; see below
```

**Federating nodes.** A node with a federation issuer (ADR 0010) binds the SHA-256 of
its federation JWKS into every quote, next to its executor key.

- `verify-execution` needs no flag for this. The signed receipt names the evidence
  document by digest, so the federation set that document binds is the receipt's fact,
  and the verifier takes it from there.
- `verify-node-evidence` has no receipt to take it from, so you state it with
  `--federation`. The default is `not-federated`. Evidence from a federating node is then
  refused, and the refusal names the digest the evidence binds:

  ```
  node evidence refused: the evidence binds federation JWKS sha256 <digest> but the
  relying party expected no federation JWKS (not federated); … Pass --federation <digest>
  after checking that it is the SHA-256 of the operator's published JWKS document, …
  ```

  Check that digest against the operator's published JWKS before you pass it. Otherwise
  you are only restating the evidence's own claim.

| Verdict | Meaning |
|---|---|
| `Attested` (exit 0) | The anchor is not `None`, the evidence is fresh at the receipt's time, and nothing in the reference's scope diverges from it. The `not_checked` list says what was not looked at, and `ima_not_in_scope` lists what was measured outside the reference's scope. |
| `Contested` | A measurement diverges, and each divergence is named. |
| `Expired` | The evidence is not fresh: a replayed challenge (`nonce_mismatch`), or epoch evidence that is too old or from the future. |
| `Unattested` | Nothing ties the quote to a TPM (no matching pin, including a software TPM with no `--allow-software-tpm-pin`), or the receipt says the node had no evidence. |
| Refusal | Not evidence at all: a bad signature, a log that does not replay, a binding to another executor key (`executor_key_mismatch`), or to another federation set (`federation_mismatch`, which names both sets). |

A browser and JavaScript verifier for node evidence, built from the same Rust verifier
compiled to wasm in `sdks/verifier-js`, is being added in a separate change.

## What a stranger cannot yet verify

- **The host boot, without the operator.** The release ships no host image, so boot
  reference values are the operator's. A published, measured host image would move them
  into the release manifest.
- **The host's kernel modules, and any other file outside the release's scope.** They
  are listed (`ima_not_in_scope`), not judged. Only the operator's reference values, or a
  published host image, can say whether they are the expected ones.
- **The AK, without the operator.** `OperatorFetched` is the operator's word, and
  `SoftwareTpm` is the operator's word about a key no hardware holds.
- **EFI applications (PCR 4).** The reference generator does not compute Authenticode
  digests yet.
- **Inside the guest.** The host TPM does not measure what runs in a Firecracker guest.
- **Whether a measured binary still runs.** IMA records a load.
- **The node's clock.** The epoch time is the node's.
- **Upstream Firecracker before the release.** The release workflow hashes the upstream
  archive as it was served at release time, and Sigstore logs that statement. Nucleus
  does not build Firecracker.
