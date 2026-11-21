# Zero static secrets

Status: proposal, 2026-11-20. Traced against `main` at `5fab70962`. Item 1 (the approval HMAC)
is done on branch `design/zero-static-secrets`, 2026-11-21, approved by the owner that day.

## What the property is

A **static secret** is a credential that someone other than the party it speaks for can use: a
boundary accepts a proof that a party besides the claimant can produce, or accepts a copy of a
proof forever. A shared HMAC key is the standard case. The verifier recomputes the MAC, so the
verifier can forge it, and so can every party the key reached on the way.

`crates/portcullis-core/lean/StaticSecrets.lean` states this as a decidable property,
`ZeroStatic`, over a list of boundaries. Each boundary is a verifier, the claimant it
authenticates, and the credentials it accepts. Each credential records how it is checked, who
can produce an accepted proof, and whether a presented proof expires. The theorems:

| theorem | says |
|---|---|
| `zero_static_no_forger` | under `ZeroStatic`, only the claimant can produce an accepted proof |
| `zero_static_proofs_expire` | under `ZeroStatic`, every accepted proof expires |
| `shared_key_is_static` | a shared key between two distinct parties is always static |
| `zero_static_no_shared_key` | so `ZeroStatic` rules out shared keys between distinct parties |
| `retire_preserves` | deleting credentials never breaks `ZeroStatic` |
| `zero_static_iff_no_violations` | `ZeroStatic` holds exactly when `violations` is empty |
| `before_violations` | on `main` at `5fab70962` (`nucleusBefore20261121`), the only violation was the tool-proxy's legacy approval HMAC |
| `workload_forged_approvals_before_20261121` | the workload could produce that HMAC then |
| `main_violations` | after the deletion, `violations nucleusMain = []` |
| `main_zero_static` | so the traced boundaries are zero-static |
| `main_is_before_with_hmac_retired` | `nucleusMain` is the earlier instance with exactly that credential filtered out |
| `only_the_approver_approves_on_main` | every approval credential on `main` has the approver as its only producer |

The instance theorems are proved by `decide` and use no axioms (`#print axioms` on
`main_violations`, `before_violations`, `main_is_before_with_hmac_retired` and
`only_the_approver_approves_on_main`, 2026-11-21); the general ones use only `propext`,
`Quot.sound` and, for one, `Classical.choice`. They can go red: restating `main_violations` over
`nucleusBefore20261121` fails with "`decide` proved that the proposition … is false" (checked
2026-11-21 with Lean 4.30.0).

## What is already done on main

An earlier version of this proposal asked to delete the node's two proxy secrets, the tier-3
sandbox token, the CLI's secret minting and its Keychain items. All of that landed between
2026-10-07 and 2026-10-13:

- The node refuses `NUCLEUS_NODE_PROXY_AUTH_SECRET` and `NUCLEUS_NODE_PROXY_APPROVAL_SECRET` by
  name at startup (`crates/nucleus-node/src/retired_config.rs`, #3391). The tier-3 token and the
  `tcp-hmac` container transport were deleted in the same change.
- The tool-proxy refuses `--auth-secret` by name (`retired::refuse_auth_secret`).
- `nucleus setup` mints no secret. It deletes the three retired Keychain items
  (`node-auth-secret`, `proxy-auth-secret`, `approval-secret`) and strips both variables from an
  existing `node.env` (`crates/nucleus-cli/src/keychain.rs`, `provision/retired_env.rs`; #3297,
  #3437). `doctor` warns on any retired item still stored.
- A pod with no SVID does not start: without an SVID or a SPIRE socket the tool-proxy exits 78
  as a naked process (`sandbox_proof.rs`, `test_naked_process_rejected`). Guests that fell back to
  tier 3 have been refused since #3391, so removing tier 3 needs no compatibility decision now.
- The operator federation key is already the documented exception. On macOS it is read and
  written only through `/usr/bin/security`, with a 5-second deadline, so a rebuilt `nucleus`
  binary never raises a dialog (`operator_key.rs`). `--key-store file` keeps it in an owner-only
  file on any platform.

## What is left

1. ~~**Delete the tool-proxy's legacy approval HMAC**~~, the one violation `before_violations`
   names. Done on this branch; see *Done on this branch* below.
2. **Trace and retire client-side HMAC in the SDKs**: `HmacAuth` in `crates/nucleus-sdk/src/auth.rs`,
   `sdks/python/nucleus_sdk/auth.py`, and the `delegation_forest.py` example. Not yet traced: which
   server boundary each still targets. Each one that is still a boundary goes into the Lean
   instance before it is deleted.
3. **Make `doctor`'s stale-item check unable to raise a dialog.** It reads the retired items
   through the Security framework from the `nucleus` binary, which is the per-binary dialog
   `operator_key.rs` was written to avoid. Running `/usr/bin/security` with a deadline, as the
   operator key store does, removes it. On a fresh Mac the items do not exist; whether the current
   check prompts there has not been run.
4. **Remove stale text and config**: `snapshot.rs` still describes node-level auth and approval
   secrets as current, and `use_keychain` in `config.rs` is written by the `setup` template and
   read by nothing that stores a secret.
5. **Decide the macOS default for the operator key**: `keychain` (today, behind
   `/usr/bin/security`) or `file`. Either satisfies `ZeroStatic`, because the key has one holder;
   this is about dialogs and backup, not about the property.
6. **Bind the instance to the code.** The instance in `StaticSecrets.lean` is hand-written from
   the trace. A census in the style of `node_state_census.rs`, one row per boundary that the
   compiler forces to be classified, would make a new boundary fail to build until it is listed.

Not in scope: the keyed hashes in `art12_shipper.rs` and `audit_log.rs` look like log integrity,
not authentication between parties; where `art12_shipper`'s key comes from has not been traced.

## Done on this branch: item 1, the approval HMAC (2026-11-21)

Approved by the owner on 2026-11-21. Each touched crate, and what it does now:

- **nucleus-tool-proxy.** `/v1/approve` accepts only an approver's Ed25519 signature against
  `--approval-pubkeys`. `auth.rs` no longer has `AuthConfig`, `verify_http_with_drand`,
  `AuthMethod::{Hmac, HmacDrand}` or `AuthTier::ApprovalHmacDrand`, and `select_auth_tier` no
  longer takes `has_approval_pubkeys`: there is one approval tier, so nothing to choose.
  `approval::ApprovalKeys` wraps the Ed25519 verifier alone, and `AppState::approval_verifier`
  is no longer an `Option`. `--approval-secret` (`NUCLEUS_TOOL_PROXY_APPROVAL_SECRET`) is hidden
  and refused by name at startup (`retired::refuse_approval_secret`, exit 78), right after
  `--auth-secret`. A proxy without `--approval-pubkeys` is refused naming both
  (`retired::require_approval_pubkeys`). A request signed the old way, with the old headers,
  framing and a shared key, fails as `InvalidSignature` (`an_hmac_signed_approval_is_refused`, in
  `auth.rs` and `approval_tests.rs`).
- **nucleus-guest-init.** `nucleus.approval_secret` and `/etc/nucleus/approval.secret` are in
  `RETIRED_SHARED_SECRETS` beside `nucleus.auth_secret` and `nucleus.sandbox_token`. When present,
  each is named in the boot log with why it is retired, and none is ever exported. This matches
  how the other two were already handled: named and dropped, not a boot failure.
  `nucleus.approval_pubkeys` is the only approval authority. A guest without it refuses to
  start, and if the retired secret is all it has, the refusal says the secret is retired, not
  missing.
- **nucleus-mcp.** The bridge already refused `--approval-secret` in every transport mode, so
  nothing ever signed with it. The flag is removed the way `--sandbox-token` was: clap rejects it
  as an unknown argument, and `NUCLEUS_MCP_APPROVAL_SECRET` is in `RETIRED_ENV`, refused by name
  at startup.
- **nucleus-client.** `sign_approval_headers` (HMAC) and `verify_drand_signature` were the client
  half of the deleted tier, and nothing else in the workspace called them. Both are deleted, and
  `sign_approval_headers_ed25519` is the only approval signer. The request signers
  (`sign_http_headers`, `sign_grpc_headers`) stay for item 2.
- **Unchanged, on purpose.** These are detectors, and they keep classifying the old name as
  secret material, so a leaked copy is still caught: `nucleus-ifc-kernel`'s `env_classifier` and
  `extracted/identity.rs`, `nucleus-tool-proxy`'s `workload.rs` classifier,
  `nucleus-escape-canary`, `nucleus-adversary-probe`, `nucleus-workload-probe`, the node's
  `spec_posture` denylist and `snapshot::PER_POD_SECRET_KEYS`. The node still `env_remove`s
  the variable before it spawns a local proxy, because a leftover in the node's environment
  would now stop every local pod.
- **Still in the tree, not changed here.** Three shell scripts:
  - `scripts/firecracker/guest-init.sh` exports `NUCLEUS_TOOL_PROXY_APPROVAL_SECRET` from a
    baked file. It is already dead: it also requires `/etc/nucleus/auth.secret`, refused since
    #2446.
  - `scripts/firecracker/build-rootfs.{sh,nu} --legacy-secrets` still bakes
    `/etc/nucleus/approval.secret`. The Rust guest-init now names that file and does not export
    it.
  - `scripts/container/smoke-test.sh` still signs with HMAC.

  Deleting them is shell work that the Rust mandate leaves to whoever next touches them.
  `check-no-hmac-auth.sh` had its header and failure text corrected, and its patterns are
  unchanged.

Lean: `nucleusBefore20261121` keeps the 2026-11-20 instance and its one violation
(`before_violations`). `nucleusMain` drops `approvalHmac`, and `main_violations` is now
`violations nucleusMain = []`. `lean StaticSecrets.lean` (Lean 4.30.0) exits 0, with no `sorry`.

Tests deleted because they exercised only the HMAC tier:

- the six `verify_http_with_drand` tests in `auth.rs`;
- `hmac_signs_only_where_no_keys_are_configured` (replaced by `an_hmac_signed_approval_is_refused`);
- `configured_pubkeys_make_the_hmac_approval_tier_unreachable`;
- `the_hmac_helper_does_not_satisfy_the_ed25519_verifier`;
- `nucleus-client`'s `test_sign_approval_headers`, `test_verify_drand_signature` and
  `empty_secret_never_verifies_drand_signature`.

**Not yet run:** none of this has been compiled or tested on this branch. The Mac it was written
on had no disk to spare for a build, so the build and test run on a VM. `nucleus verify --tier2`
on a real host (Done means, below) is also still to do.

## Done means

- `main_violations` is changed to `violations nucleusMain = []`, with the instance updated to the
  code after the deletion, and it holds.
- `grep` finds no reader of `NUCLEUS_TOOL_PROXY_APPROVAL_SECRET` or `nucleus.approval_secret`
  outside the code that refuses them by name.
- A tool-proxy test drives an HMAC-signed approval to refusal.
- `nucleus verify --tier2` passes on a real host.

Status on this branch, 2026-11-21, item 1:

- The first bullet holds; Lean checked it.
- The second holds for Rust: the remaining mentions are refusals, detectors, or a negative test.
  The one reader left is the shell script `scripts/firecracker/guest-init.sh`, already dead
  (above).
- The third is written but not yet run.
- The fourth is not run.

Estimate: under a day for items 1 and 4, plus the SDK trace in item 2. Most of it is tests.
