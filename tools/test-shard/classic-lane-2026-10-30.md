# 2026-10-30: why #3512's last head is decided on the classic arm64 lane

`tools/test-shard` generates the `clippy-libs` and `test-libs` shards, so the note about the lane
those two gates ran on for #3512 is kept here.

**What happened.** #3512's head `7a61338f8` (tree `384ec3bf4`) was decided on the trusted-launch
lane (node `node-9e7b2c870`). Eight required gates held. `clippy-libs` (leaf 18120) and `test-libs`
(leaf 18126) failed with `unshare: Operation not permitted`. Their recipes `unshare` a mount
namespace to put the workspace at the path the verifier SDK's digest pins. The trusted launcher
refuses that. The launcher's workspace bind would replace it, but only a plan that declares
`checkout_at` asks for the bind, and main's served plan does not declare it yet (#3511, gatehouse
F-322).

**Why the classic lane.** On the classic stack (node `cb47c1b64`, agent `6ed2dfda7`) the same two
recipes run their `unshare` and hold. #3511's did, on main's served plan. A verdict is final for its
tree, so a new tree has to be decided. This file is that change.

**Why the note is here and not under `docs/`.** Every path under `docs/**` is in `text-north-star`'s
scope. On the classic node `text-north-star` fails for every head, because the escape canary's
`svid_key_later_fetch` is a breach there (the node predates #3080). That failure is the node's, not
the tree's. This path is in the scope of `clippy-libs`, `test-libs`, `clippy-node` and `test-node`,
which re-run on classic. `text-north-star`'s scope does not change, so the kernel reuses its held
receipt from tree `384ec3bf4` (leaf 18123, trusted-launch). That receipt is for the same gate
definition and the same scope contents. Each verdict in the roll-up names its node in its receipt.

**Do not run a plan that declares `checkout_at` on classic.** The classic agent parses steps with
`deny_unknown_fields` and refuses the job (gatehouse F-325). After #3511 merges, the lane goes back
to trusted-launch.
