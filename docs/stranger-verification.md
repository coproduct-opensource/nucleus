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
- **Everything else** (Secure Boot state, EFI applications, boot files, kernel command
  line, PCR pins) is `not_checked`, with the reason written into the manifest. The
  appraisal prints every `not_checked` item beside its verdict. An `Attested` result
  against the release manifest alone therefore says nothing about the host's boot, and
  says so.
- **Install paths.** The paths are where `nucleus setup` installs (`/usr/local/bin`). IMA
  records the path after symlinks resolve. A node that keeps its binaries on a dedicated
  filesystem (the narrow-IMA layout in `docs/findings/attested-node-live-run.md`)
  regenerates the manifest with `--install-dir` from the same signed tarballs. The
  digests do not change; only the paths do.

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
statement, in the same way the AK pin is.

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
  --operator-pin 'SOURCE=<spki-sha256>'
```

| Verdict | Meaning |
|---|---|
| `Attested` (exit 0) | The anchor is not `None`, the evidence is fresh at the receipt's time, and nothing diverges from the reference. The `not_checked` list says what was not looked at. |
| `Contested` | A measurement diverges, and each divergence is named. |
| `Expired` | The evidence is not fresh: a replayed challenge (`nonce_mismatch`), or epoch evidence that is too old or from the future. |
| `Unattested` | Nothing ties the quote to a TPM (no matching pin), or the receipt says the node had no evidence. |
| Refusal | Not evidence at all: a bad signature, a log that does not replay, or a binding to another executor key. |

A browser and JavaScript verifier for node evidence, built from the same Rust verifier
compiled to wasm in `sdks/verifier-js`, is being added in a separate change.

## What a stranger cannot yet verify

- **The host boot, without the operator.** The release ships no host image, so boot
  reference values are the operator's. A published, measured host image would move them
  into the release manifest.
- **The AK, without the operator.** `OperatorFetched` is the operator's word.
- **EFI applications (PCR 4).** The reference generator does not compute Authenticode
  digests yet.
- **Inside the guest.** The host TPM does not measure what runs in a Firecracker guest.
- **Whether a measured binary still runs.** IMA records a load.
- **The node's clock.** The epoch time is the node's.
- **Upstream Firecracker before the release.** The release workflow hashes the upstream
  archive as it was served at release time, and Sigstore logs that statement. Nucleus
  does not build Firecracker.
