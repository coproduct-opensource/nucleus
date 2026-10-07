# Release-journey evidence

Three runs of a coding agent in a nucleus pod on published releases. Each was recorded so that
anyone can re-check it with that release's published `nucleus-audit` and nothing else, by the
method in [Verifying a receipt as a stranger](../stranger-verification.md).

In every run, an agent repaired `summary.py` in the public
[fixture repository](https://github.com/coproduct-opensource/nucleus-journey-fixture). The pod
held no forge credential. The node performed the push and the pull request itself, and held
each one until the owner approved it.

## Where the records are

The signed records are published on the fixture repository's `evidence` branch, pinned at
commit
[`8eaafc4be1dd419896235977eb1fa0d719984b3e`](https://github.com/coproduct-opensource/nucleus-journey-fixture/tree/8eaafc4be1dd419896235977eb1fa0d719984b3e).
Each run's directory keeps the signed files exactly as the node wrote them, and has a
`README.md` and a `REDACTION.md`. They are kept out of this repository because they are
verbatim records of an operator's run, and no signed byte may be edited. Among other things
they record the operator's choice of coding-model upstream and model.

```sh
git clone --branch evidence https://github.com/coproduct-opensource/nucleus-journey-fixture.git
git -C nucleus-journey-fixture checkout --detach 8eaafc4be1dd419896235977eb1fa0d719984b3e
git -C nucleus-journey-fixture rev-parse HEAD   # must print 8eaafc4be1dd419896235977eb1fa0d719984b3e
```

| Run | Release | Node | Harness | Platform tier | AK anchor | Result |
|---|---|---|---|---|---|---|
| [`v2.6.0-attested-aider`](https://github.com/coproduct-opensource/nucleus-journey-fixture/tree/8eaafc4be1dd419896235977eb1fa0d719984b3e/v2.6.0-attested-aider) | v2.6.0 | x86_64 GCP Shielded VM, vTPM | aider 0.86.2 | **Attested** with the operator's AK pin; **Unattested** without it | `operator_fetched` | [PR #4](https://github.com/coproduct-opensource/nucleus-journey-fixture/pull/4) |
| [`v2.5.0-mac-aider`](https://github.com/coproduct-opensource/nucleus-journey-fixture/tree/8eaafc4be1dd419896235977eb1fa0d719984b3e/v2.5.0-mac-aider) | v2.5.0 | aarch64 Apple `container` dev host, no TPM | aider 0.86.2 | **Unattested** | none | [PR #1](https://github.com/coproduct-opensource/nucleus-journey-fixture/pull/1) |
| [`v2.5.0-mac-opencode`](https://github.com/coproduct-opensource/nucleus-journey-fixture/tree/8eaafc4be1dd419896235977eb1fa0d719984b3e/v2.5.0-mac-opencode) | v2.5.0 | aarch64 Apple `container` dev host, no TPM | opencode 1.18.34 | **Unattested** | none | [PR #2](https://github.com/coproduct-opensource/nucleus-journey-fixture/pull/2) |

The fixture's PRs stay open and are never merged.

## What the verdicts say, and what they rest on

**v2.6.0, attested node.** `verify-execution --require-attested`, checked against the
published, cosign-verified `nucleus-2.6.0-x86_64.node-reference.json`, returns these results:

- verdict `authorized_on_an_attested_node`, tier `attested`, EAR status `affirming`;
- anchor `operator_fetched`, source `gcp-shielded-vm-identity:nucleus-attest-node-202610070156`;
- in the IMA scope `/usr/local/bin`: `nucleus-node`, `firecracker` and `jailer`, all on the
  release allowlist, with no divergences;
- 64 kernel modules under `ima_not_in_scope`, measured by the platform's Secure Boot policy and
  vouched for by nobody;
- `not_checked`: Secure Boot, EFI applications, boot files and the kernel command line. The
  release publishes no host image, so the release manifest checks none of these, and the
  result says nothing about the host's boot.

The trust assumption is the AK pin. This VM type has no platform-issued AK or EK certificate,
so nothing a stranger can check cryptographically ties the quote's attestation key to a TPM.
The pin, `gcp-shielded-vm-identity:nucleus-attest-node-202610070156=6e8ab634f572c777352d62e2f6a7da1b53fc9d2ae8bd3d667a4a0646a744ef8d`,
is the operator's statement of what the cloud provider's authenticated `get-shielded-identity`
API reported for this VM. The VM was deleted after the run, so nobody can fetch the pin again,
and an `Attested` reading is exactly as good as your trust in that statement. The same digest
appears inside the quote. Copying it from there would be circular. Without the pin the tier is
`Unattested` (`ak_unanchored: no_matching_operator_pin`). The host-effect key is also the
operator's word. The executor key is bound into the TPM quote, and the verifier refuses
evidence that binds a different one.

**v2.5.0, Mac host (both runs).** `verify-execution` returns `authorized_platform_not_attested`,
tier `unattested`, `from: receipt`. The signed receipt records that the node had no TPM, and
evidence supplied beside a receipt can never upgrade that. These runs make no claim about the
host's boot or binaries. What they do establish:

- the receipt is signed by the executor key and agrees with the admission and the environment
  inputs;
- the artifacts and console logs are the bytes the receipt names;
- the held push and pull request carry node-signed authorizations and outcomes.

Both keys are the operator's statement.

## Re-verify a run

Each block takes the run's directory as its first argument and defaults to the run's name in
the current directory. You need `gh`, `cosign` and `jq`, and `openssl` for v2.6.0. Every command
in "checks" should exit 0, and every command in "controls" should exit 1.

### v2.6.0-attested-aider

```sh
B=${1:-./nucleus-journey-fixture/v2.6.0-attested-aider}
R=$(mktemp -d)
gh release download v2.6.0 --repo coproduct-opensource/nucleus --dir "$R" \
  --pattern 'nucleus-audit-2.6.0-aarch64-apple-darwin.tar.gz*' \
  --pattern 'nucleus-2.6.0-x86_64.node-reference.json*'
for f in nucleus-audit-2.6.0-aarch64-apple-darwin.tar.gz nucleus-2.6.0-x86_64.node-reference.json; do
  cosign verify-blob --bundle "$R/$f.sigstore.json" \
    --certificate-identity https://github.com/coproduct-opensource/nucleus/.github/workflows/release.yml@refs/tags/v2.6.0 \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$R/$f"
done
tar xzf "$R/nucleus-audit-2.6.0-aarch64-apple-darwin.tar.gz" -C "$R"
cmp "$R/nucleus-2.6.0-x86_64.node-reference.json" "$B/release-manifest/nucleus-2.6.0-x86_64.node-reference.json"

A=$R/nucleus-audit
RREF=$R/nucleus-2.6.0-x86_64.node-reference.json
PIN='gcp-shielded-vm-identity:nucleus-attest-node-202610070156=6e8ab634f572c777352d62e2f6a7da1b53fc9d2ae8bd3d667a4a0646a744ef8d'
SIGNER=$(jq -r .executor.public_key_hex "$B/node-evidence/node-keys.json")
HOSTPUB=c80b7a5b991858937f16eb93e254cad1432df7b1483af57a93dc1eebf2b393da
FED=$(jq -r .binding.federation.jwks_sha256 "$B/node-evidence/evidence-epoch.json")
POD=$(cat "$B/receipt/pod_id")
VALID=$(( ($(date +%s) + 86400) * 1000000 ))
X=$(mktemp -d)

# Expectations, from the run's own admission. A real relying party states its own.
$A prepare-execution --admission "$B/receipt/admission.json" --signer-key-hex "$SIGNER" \
  --environment-inputs "$B/receipt/env-inputs.json" --valid-until-micros "$VALID" > "$X/expected-receipt.json"
for k in a b c; do
  $A prepare-execution --admission "$B/receipt/admission.json" --signer-key-hex "$SIGNER" \
    --environment-inputs "$B/receipt/env-inputs.json" --valid-until-micros "$VALID" \
    --artifacts "$B/artifacts/artifacts-$k.json" > "$X/expected-$k.json"
done

# Checks (exit 0).
$A verify-execution --receipt "$B/receipt/receipt.json" --expectations "$X/expected-receipt.json" \
  --node-evidence "$B/node-evidence/evidence-epoch.json" --node-reference "$RREF" \
  --operator-pin "$PIN" --require-attested
$A verify-node-evidence --evidence "$B/node-evidence/evidence-challenge.json" --reference "$RREF" \
  --executor-ed25519 "$SIGNER" --federation "$FED" \
  --nonce "$(cat "$B/node-evidence/challenge-nonce.txt")" --operator-pin "$PIN"
$A verify-logs --receipt "$B/receipt/receipt.json" --expectations "$X/expected-receipt.json" \
  --stdout "$B/logs/stdout.bin" --stderr "$B/logs/stderr.bin"
for k in a b c; do
  $A verify-artifacts --bundle "$B/artifacts/bundle-$k.json" --expectations "$X/expected-$k.json"
done
$A verify-host-effects --log "$B/host-effects/host-effect-authorizations.jsonl" \
  --outcomes "$B/host-effects/host-effect-outcomes.jsonl" --host-pubkey "$HOSTPUB" --pod "$POD"

# Controls (exit 1).
T=$B/verify/tamper-inputs
$A verify-execution --receipt "$B/receipt/receipt.json" --expectations "$X/expected-receipt.json" \
  --node-evidence "$B/node-evidence/evidence-epoch.json" --node-reference "$RREF" --require-attested
$A verify-execution --receipt "$B/receipt/receipt.json" --expectations "$X/expected-receipt.json" \
  --node-evidence "$B/node-evidence/evidence-epoch.json" --node-reference "$RREF" \
  --operator-pin "${PIN%?}0" --require-attested
$A verify-execution --receipt "$B/receipt/receipt.json" --expectations "$X/expected-receipt.json" \
  --node-evidence "$B/node-evidence/evidence-epoch.json" --node-reference "$T/manifest-wrong-node-digest.json" \
  --operator-pin "$PIN" --require-attested
$A verify-execution --receipt "$B/receipt/receipt.json" --expectations "$X/expected-receipt.json" \
  --node-evidence "$T/evidence-epoch.json" --node-reference "$RREF" --operator-pin "$PIN" --require-attested
$A verify-node-evidence --evidence "$B/node-evidence/evidence-challenge.json" --reference "$RREF" \
  --executor-ed25519 "$SIGNER" --federation "$FED" --nonce "$(openssl rand -hex 32)" --operator-pin "$PIN"
$A verify-node-evidence --evidence "$B/node-evidence/evidence-epoch.json" --reference "$RREF" \
  --executor-ed25519 "$SIGNER" --federation "$FED" --max-age-secs 900 \
  --receipt-time $(( $(jq .freshness.epoch.iat "$B/node-evidence/evidence-epoch.json") + 3600 )) \
  --operator-pin "$PIN"
$A verify-node-evidence --evidence "$B/node-evidence/evidence-challenge.json" --reference "$RREF" \
  --executor-ed25519 "$SIGNER" --nonce "$(cat "$B/node-evidence/challenge-nonce.txt")" --operator-pin "$PIN"
$A verify-execution --receipt "$T/receipt.json" --expectations "$X/expected-receipt.json"
$A verify-artifacts --bundle "$T/bundle-a.json" --expectations "$X/expected-a.json"
$A verify-logs --receipt "$B/receipt/receipt.json" --expectations "$X/expected-receipt.json" \
  --stdout "$T/stdout.bin" --stderr "$B/logs/stderr.bin"
$A verify-host-effects --log "$T/host-effect-authorizations.jsonl" --host-pubkey "$HOSTPUB" --pod "$POD"
$A verify-host-effects --log "$B/host-effects/host-effect-authorizations.jsonl" \
  --host-pubkey "${HOSTPUB%?}0" --pod "$POD"
```

| Control (12) | Refusal |
|---|---|
| no pin, wrong pin | `Unattested`: `ak_unanchored: no_matching_operator_pin` |
| manifest with `nucleus-node`'s digest altered | `Contested`: `ima_file_not_allowed` + `ima_required_missing` |
| evidence not named by the receipt | its SHA-256 is not the one the receipt names |
| replayed challenge, stale epoch | `Expired`: `nonce_mismatch`, `too_old` |
| no `--federation` | refused, naming the bound JWKS digest |
| tampered receipt root hash, artifact, stdout | `root hash mismatch`, `artifact bytes differ from signed identity`, `Log("stdout")` |
| tampered host-effect record, wrong host key | `host signature does not verify` |

### v2.5.0-mac-aider and v2.5.0-mac-opencode

```sh
B=${1:-./nucleus-journey-fixture/v2.5.0-mac-aider}   # or ./nucleus-journey-fixture/v2.5.0-mac-opencode
R=$(mktemp -d)
gh release download v2.5.0 --repo coproduct-opensource/nucleus --dir "$R" \
  --pattern 'nucleus-audit-2.5.0-aarch64-apple-darwin.tar.gz*'
cosign verify-blob --bundle "$R/nucleus-audit-2.5.0-aarch64-apple-darwin.tar.gz.sigstore.json" \
  --certificate-identity https://github.com/coproduct-opensource/nucleus/.github/workflows/release.yml@refs/tags/v2.5.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$R/nucleus-audit-2.5.0-aarch64-apple-darwin.tar.gz"
tar xzf "$R/nucleus-audit-2.5.0-aarch64-apple-darwin.tar.gz" -C "$R"

A=$R/nucleus-audit
SIGNER=79193ef659f26ad03f62e5c1bf42eafd24e3d44295af26943af1d42ac898dab2    # executor, enrolled 2026-10-05
HOSTPUB=c7708cfc1b26771ce116c78555f08ed79f142ca335afcb7e9a3de8ba009b2114   # host cert root
POD=$(cat "$B/receipt/pod_id")
VALID=$(( ($(date +%s) + 86400) * 1000000 ))
X=$(mktemp -d)

$A prepare-execution --admission "$B/receipt/admission.json" --signer-key-hex "$SIGNER" \
  --environment-inputs "$B/receipt/env-inputs.json" --valid-until-micros "$VALID" > "$X/expected-receipt.json"
for k in a b c; do
  $A prepare-execution --admission "$B/receipt/admission.json" --signer-key-hex "$SIGNER" \
    --environment-inputs "$B/receipt/env-inputs.json" --valid-until-micros "$VALID" \
    --artifacts "$B/artifacts/artifacts-$k.json" > "$X/expected-$k.json"
done

# Checks (exit 0).
$A verify-execution --receipt "$B/receipt/receipt.json" --expectations "$X/expected-receipt.json"
$A verify-logs --receipt "$B/receipt/receipt.json" --expectations "$X/expected-receipt.json" \
  --stdout "$B/logs/stdout.bin" --stderr "$B/logs/stderr.bin"
for k in a b c; do
  $A verify-artifacts --bundle "$B/artifacts/bundle-$k.json" --expectations "$X/expected-$k.json"
done
$A verify-host-effects --log "$B/host-effects/host-effect-authorizations.jsonl" \
  --outcomes "$B/host-effects/host-effect-outcomes.jsonl" --host-pubkey "$HOSTPUB" --pod "$POD"

# Controls (exit 1).
T=$B/verify/tamper-inputs
$A verify-execution --receipt "$B/receipt/receipt.json" --expectations "$X/expected-receipt.json" --require-attested
$A verify-execution --receipt "$T/receipt.json" --expectations "$X/expected-receipt.json"
$A verify-artifacts --bundle "$T/bundle-a.json" --expectations "$X/expected-a.json"
$A verify-logs --receipt "$B/receipt/receipt.json" --expectations "$X/expected-receipt.json" \
  --stdout "$T/stdout.bin" --stderr "$B/logs/stderr.bin"
$A verify-host-effects --log "$T/host-effect-authorizations.jsonl" --host-pubkey "$HOSTPUB" --pod "$POD"
$A verify-host-effects --log "$B/host-effects/host-effect-authorizations.jsonl" \
  --host-pubkey "${HOSTPUB%?}0" --pod "$POD"
```

The 6 controls are refused as follows. `--require-attested` fails with
`the node platform is not attested`, because the receipt says `unattested`. The tampered
receipt fails with `root hash mismatch`, the tampered artifact with
`artifact bytes differ from signed identity`, and the tampered stdout with `Log("stdout")`. The
tampered host-effect record and the wrong host key both fail with
`host signature does not verify`.
