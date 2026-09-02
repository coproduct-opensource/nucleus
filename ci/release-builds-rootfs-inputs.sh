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

# release.yml now also runs on a schedule as a DRY RUN. Publishing must stay
# tag-only, or a nightly build would cut a release nobody asked for. `publish`
# and `homebrew` both `needs: release`, so this one guard covers all three.
# Read the `release` job's OWN if:, not the whole file. The dry-run job carries a
# NEGATED copy of this same expression, so a file-wide grep is satisfied by the
# wrong line and the guard passes with the real one deleted (observed).
release_if=$(awk '
  /^  release:/            { in_job = 1; next }
  in_job && /^  [a-z_-]+:/ { exit }
  in_job && /^    if:/     { print; exit }
' "$RELEASE_YML")

if printf %s "$release_if" | grep -q -- "!startsWith(github.ref"; then
  echo "::error::the release job if: NEGATES the tag check: $release_if"
  echo "  As written, publishing happens on the nightly dry run and NOT on a tag."
  fail=1
elif ! printf %s "$release_if" | grep -qF "startsWith(github.ref, 'refs/tags/')"; then
  echo "::error::$RELEASE_YML no longer gates publishing on a tag. It runs on a"
  echo "  schedule; without that guard a nightly dry run would publish a release."
  echo "  release job if: ${release_if:-<none found>}"
  fail=1
fi

# The floating major tag must move through the refs API, never `git push`.
# GITHUB_TOKEN cannot push a ref whose .github/workflows/ differs from a branch
# tip, which is the normal state of a release tag -- so a `git push` here fails
# the release AFTER every asset has uploaded. Regressing this is silent until
# the next release, which is exactly the class of rot the dry run cannot see:
# the step is tag-only, so no dry run ever executes it.
float_step=$(awk '
  /Update floating major tag/ { in_step = 1 }
  in_step && /^      - name:/ && !/Update floating major tag/ { exit }
  in_step { print }
' "$RELEASE_YML")

if [ -z "$float_step" ]; then
  echo "::error::$RELEASE_YML has no 'Update floating major tag' step; consumers pin @v2."
  fail=1
elif printf %s "$float_step" | grep -qE '^[^#]*git push'; then
  echo "::error::the floating major tag is moved with 'git push' in $RELEASE_YML."
  echo "  GITHUB_TOKEN is refused when the tag's .github/workflows/ differs from a"
  echo "  branch tip -- the normal case. Use the git refs API instead."
  fail=1
fi

# release.yml is not the only consumer of this list. `cross-build.sh` builds the
# same binaries for a LOCAL rootfs, and build-rootfs.sh points users at it by
# name when one is missing. It hand-maintained its own array, that array omitted
# nucleus-adversary-probe, and because build-rootfs.sh copies that probe with a
# bare `[ -f ]` the local rootfs came out exit-0 with the probe absent (#2377).
#
# Asked BEHAVIOURALLY -- run the script and compare what it would build -- rather
# than by grepping its source, so it keeps working whether the list is derived or
# literal.
CROSS_SH="scripts/cross-build.sh"
if [ ! -f "$CROSS_SH" ]; then
  echo "::error::$CROSS_SH missing; the local rootfs path is unchecked"
  fail=1
elif ! cross_list=$(bash "$CROSS_SH" --list-packages 2>/dev/null); then
  echo "::error::$CROSS_SH --list-packages failed; cannot tell what a local build produces."
  echo "  That flag is what makes this check behavioural instead of a grep."
  fail=1
else
  # printf '%s\n', not printf %s: without the trailing newline the last element
  # has no line terminator, which both mangles the report and can hide an entry
  # from `comm`.
  cross_sorted=$(printf '%s\n' "$cross_list" | sort -u)
  needed_sorted=$(printf '%s\n' "$needed" | sort -u)
  missing_from_cross=$(comm -23 <(printf '%s\n' "$needed_sorted") <(printf '%s\n' "$cross_sorted"))
  if [ -n "$missing_from_cross" ]; then
    echo "::error::$CROSS_SH does not build binaries the rootfs needs:"
    printf '%s\n' "$missing_from_cross" | sed 's/^/  missing: /'
    echo "  build-rootfs.sh copies some of these with a bare [ -f ], so the rootfs"
    echo "  would build successfully and simply not contain them."
    fail=1
  fi
fi

# The tag trigger must NOT match the floating major tag this workflow moves.
# `v*` matches `v2`, so the workflow triggers itself on the tag it just moved,
# rebuilds everything, and publishes a Release named "v2" that becomes Latest --
# which is what scripts/install.sh resolves. Observed 2026-09-02.
tag_filters=$(awk '
  /^  push:/       { in_push = 1; next }
  in_push && /^  [a-z_-]+:/ { exit }
  in_push && /^      - "/   { print }
' "$RELEASE_YML")

if [ -z "$tag_filters" ]; then
  echo "::error::$RELEASE_YML has no push tag filters; cannot tell what triggers a release."
  fail=1
elif printf %s "$tag_filters" | grep -qE '^\s*- "v\*"\s*$'; then
  echo "::error::$RELEASE_YML triggers on the bare glob \"v*\", which matches the"
  echo "  floating major tag (v2) that this workflow moves itself. That publishes a"
  echo "  second Release named after the floating tag, and it becomes Latest."
  echo "  Use \"v*.*.*\" so only versioned tags cut a release."
  fail=1
fi

# Third consumer: quickstart-boot.yml builds the guest binaries for the rootfs it
# boots. Its list was ALSO hand-maintained and ALSO missing one -- podlist-probe
# -- so the pod CI boots had no podlist probe in it. That is the same drift as
# release.yml (#2366) and cross-build.sh (#2377), a third time.
#
# Accept either shape: derive from cross-build.sh (preferred), or name every
# needed package literally. What is not acceptable is naming SOME of them.
QUICKSTART_YML=".github/workflows/quickstart-boot.yml"
if [ ! -f "$QUICKSTART_YML" ]; then
  echo "::error::$QUICKSTART_YML missing; the booted-rootfs path is unchecked"
  fail=1
elif grep -q 'cross-build.sh --list-packages' "$QUICKSTART_YML"; then
  : # derived — cannot drift
else
  for bin in $needed; do
    grep -q -- "-p ${bin}" "$QUICKSTART_YML" \
      || { echo "::error::$QUICKSTART_YML never builds ${bin}, so the rootfs it boots will not contain it"; fail=1; }
  done
fi

[ "$fail" -eq 0 ] && echo "ok: release.yml builds and uploads all $n rootfs inputs"
exit $fail
