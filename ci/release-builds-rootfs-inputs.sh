#!/usr/bin/env bash
# Every guest binary the rootfs needs must be BUILT and UPLOADED by release.yml.
#
# WHY: `build-rootfs.sh` requires seven guest binaries. `release.yml` built
# three. The rootfs job runs on a different runner and sees only what the build
# job uploads, so a binary missing from EITHER list fails the release with:
#
#   Missing target/<triple>/release/nucleus-workload-probe
#
# Four probes were added to the rootfs over time and never added to the
# workflow. Nobody noticed because the failure only surfaces when a release is
# actually cut, and the previous one was v2.1.0 in July — so the rootfs job was
# broken for however long that drift existed, and v2.2.0 is what found it. It
# also explains why `nucleus-egress-probe` was absent from the shipped v2.1.0
# rootfs: it was never built.
#
# Two lists that must agree, in two files, is exactly the shape that drifts.
set -euo pipefail
cd "$(dirname "$0")/.."

ROOTFS_SH="scripts/firecracker/build-rootfs.sh"
RELEASE_YML=".github/workflows/release.yml"
for f in "$ROOTFS_SH" "$RELEASE_YML"; do
  [ -f "$f" ] || { echo "::error::$f missing"; exit 1; }
done

# What the rootfs asks for: the `*_BIN` defaults name each crate's artifact.
needed=$(grep -oE 'release/nucleus-[a-z-]+' "$ROOTFS_SH" | sed 's|release/||' | sort -u)
[ -n "$needed" ] || { echo "::error::parsed no binaries from $ROOTFS_SH — check would be vacuous"; exit 1; }

fail=0
n=0
for bin in $needed; do
  n=$((n + 1))
  grep -q "cross build -p ${bin} " "$RELEASE_YML" \
    || { echo "::error::$RELEASE_YML never BUILDS ${bin} (needed by $ROOTFS_SH)"; fail=1; }
  grep -q "release/${bin}$" "$RELEASE_YML" \
    || { echo "::error::$RELEASE_YML never UPLOADS ${bin} — the rootfs job runs on another runner and will not see it"; fail=1; }
done

# Non-vacuity: the rootfs genuinely needs several binaries. If this ever parses
# one or zero, the parse broke rather than the requirement shrinking.
if [ "$n" -lt 5 ]; then
  echo "::error::only $n binaries parsed from $ROOTFS_SH; the parse looks broken"
  exit 1
fi

[ "$fail" -eq 0 ] && echo "ok: release.yml builds and uploads all $n rootfs inputs"
exit $fail
