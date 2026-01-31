#!/usr/bin/env bash
set -euo pipefail

SCRATCH_IMG=${SCRATCH_IMG:-./build/firecracker/scratch.ext4}
SCRATCH_SIZE=${SCRATCH_SIZE:-256M}

mkdir -p "$(dirname "$SCRATCH_IMG")"

rm -f "$SCRATCH_IMG"

# Create an empty ext4 image for writable scratch.
MKE2FS_OPTS=${MKE2FS_OPTS:-"-t ext4 -m 0 -F"}
# shellcheck disable=SC2086
mke2fs $MKE2FS_OPTS "$SCRATCH_IMG" "$SCRATCH_SIZE"

echo "scratch image written to $SCRATCH_IMG"
