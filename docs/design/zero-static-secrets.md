# Zero static secrets

Status: proposal, 2026-11-20. Traced against `main` at `5fab70962`.

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
| `main_violations` | on `main`, the only violation is the tool-proxy's legacy approval HMAC |
| `target_zero_static` | with that credential retired, the traced boundaries are zero-static |
| `workload_forges_approvals_on_main` | the workload can produce that HMAC today |

The instance theorems are proved by `decide` and use no axioms; the general ones use only
`propext`, `Quot.sound` and, for one, `Classical.choice`. Turning the legacy HMAC into a public-key
credential in the instance fails `main_violations` and `main_not_zero_static`, so those two can
go red.

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

1. **Delete the tool-proxy's legacy approval HMAC**, the one violation `main_violations` names.
   - The tool-proxy: `--approval-secret` (`NUCLEUS_TOOL_PROXY_APPROVAL_SECRET`), the `Hmac` arm
     of `approval.rs`, and the HMAC verification in `auth.rs` that only it reaches.
   - `guest-init`: stop reading `nucleus.approval_secret` and `/etc/nucleus/approval.secret`, and
     refuse both by name, as it already refuses `nucleus.auth_secret` and `nucleus.sandbox_token`.
   - The node has not emitted `nucleus.approval_secret` since approvals moved to Ed25519
     (`firecracker_config.rs`), so only a hand-built image or a hand-set boot argument reaches this
     path. Such an image, if it carries no `nucleus.approval_pubkeys`, will refuse at
     `guest-init`. `guest-init` already refuses a guest that has neither.
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

## Done means

- `main_violations` is changed to `violations nucleusMain = []`, with the instance updated to the
  code after the deletion, and it holds.
- `grep` finds no reader of `NUCLEUS_TOOL_PROXY_APPROVAL_SECRET` or `nucleus.approval_secret`
  outside the code that refuses them by name.
- A tool-proxy test drives an HMAC-signed approval to refusal.
- `nucleus verify --tier2` passes on a real host.

Estimate: under a day for items 1 and 4, plus the SDK trace in item 2. Most of it is tests.
