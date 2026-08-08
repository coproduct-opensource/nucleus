#!/usr/bin/env bash
# C1 inbound-fence ENFORCEMENT gate — the runtime conformance behind the
# re-promotion of North Star clause C1 ("cannot learn the secrets Nucleus holds
# on its behalf").
#
# WHY THIS EXISTS
#
# C1's relation leg is proven in Lean (identity material and the seven
# child-inheritance channels — including Cmdline — never deliver a secret to the
# workload). But the Lean theorem does not say the RUNTIME withholds; that is
# the conformance leg, and a red-team walk of the residual inbound surfaces
# (docs/north-star.md, the C1 note) found two that were fenced only
# conditionally or not at all:
#
#   B  /proc/<pid>/environ — the runtime holds every per-pod secret in its own
#      environment; a workload sharing the runtime's uid reads it. The uid fence
#      was wired ONLY under credentialed egress, so a no-egress, no-uid pod ran
#      the workload as root and was exposed.
#   D  the env classifier's `_ => OrdinaryData` fallthrough — a NUCLEUS_* name it
#      does not recognise fell through to Public and was delivered, and the
#      dual-classifier corpus test could not catch it (both classifiers share
#      the OrdinaryData default).
#
# Both are now fail-closed at admission (crates/nucleus-tool-proxy/src/workload.rs):
# every workload runs as a distinct unprivileged uid (never the runtime's), and
# any unclassified reserved-namespace key is refused. This gate runs the tests
# that red if either fence is reverted, plus the Cmdline-channel conformance
# tests that red if a per-pod secret reappears on the guest command line.
#
# So this gate does NOT re-assert the Lean relation (the aeneas / portcullis-core
# proof workflows do). It asserts the shipping runtime enforces what the relation
# assumes — which is what makes C1 true on the live path, not just in the model.
#
# Usage: scripts/check-c1-inbound-fences.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

echo "Asserting the C1 inbound fences are enforced (not just proven in the model)..."

# B — the workload never runs as the runtime's uid. A no-uid pod is assigned a
# distinct default; an explicit runtime-uid is refused; a distinct uid is kept.
# Reverting the fence to the egress-only coupling reds these.
cargo test -p nucleus-tool-proxy -- \
    workload::tests::admit_assigns_a_distinct_default_uid_when_none_is_set \
    workload::tests::admit_refuses_a_workload_sharing_the_runtime_uid \
    workload::tests::admit_preserves_an_explicit_distinct_uid

# D — an unclassified NUCLEUS_* key is refused at admission, not delivered as
# OrdinaryData. Reverting the reserved-namespace fence reds this.
cargo test -p nucleus-tool-proxy -- \
    workload::tests::an_unclassified_reserved_namespace_key_is_refused

# Cmdline channel conformance — no per-pod secret rides the guest /proc/cmdline
# (the channel whose omission demoted C1 in the first place), at both the
# node-side construction and the extracted channel-admission model.
#
# The node-side construction tests exercise `FirecrackerConfig::from_spec`, which
# is `#[cfg(target_os = "linux")]` (the Firecracker path compiles on Linux only),
# so they run under CI's ubuntu runner and are skipped on a macOS dev box (where
# they would not compile). The extracted channel-admission model below is
# cross-platform and always runs.
if [[ "$(uname -s)" == "Linux" ]]; then
    cargo test -p nucleus-node -- \
        no_pod_cmdline_carries_any_per_pod_secret \
        a_cmdline_that_carries_a_per_pod_secret_is_still_refused
else
    echo "  (skipping the Linux-only cmdline construction tests on $(uname -s); they run in CI)"
fi
cargo test -p nucleus-ifc-kernel --lib -- extracted::channel

echo "OK: the C1 inbound fences (uid distinctness, reserved-namespace, cmdline) are enforced."
