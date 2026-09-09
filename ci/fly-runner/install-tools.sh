#!/usr/bin/env bash
# Install only checksum-pinned executables, and never an archive's own paths: each tool is the
# single file in its archive with the expected name, extracted to stdout and written where this
# script decides. An archive that carries two of them, or none, is a failed build rather than a
# surprise on the executable search path.
set -euo pipefail
manifest=${1:?usage: install-tools.sh <tools.json>}
count=$(jq 'length' "$manifest")
for i in $(seq 0 $((count - 1))); do
  url=$(jq -r ".[$i].url" "$manifest")
  want=$(jq -r ".[$i].sha256" "$manifest")
  binary=$(jq -r ".[$i].binary" "$manifest")
  archive=$(mktemp)
  curl -fsSL --retry 3 "$url" -o "$archive"
  got=$(sha256sum "$archive" | cut -d' ' -f1)
  [ "$got" = "$want" ] || { echo "checksum mismatch: $binary ($got)" >&2; exit 1; }
  member=$(tar -tzf "$archive" | awk -F/ -v b="$binary" 'substr($0,length($0))!="/" && $NF==b')
  [ "$(printf '%s' "$member" | grep -c .)" -eq 1 ] || { echo "ambiguous executable: $binary" >&2; exit 1; }
  tar -xzOf "$archive" "$member" > "/usr/local/bin/$binary"
  chmod 0755 "/usr/local/bin/$binary"
  rm -f "$archive"
done
