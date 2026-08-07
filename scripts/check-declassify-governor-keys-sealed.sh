#!/usr/bin/env bash
# Governor-key SEAL gate — robust declassification at the *who* dimension.
#
# WHY THIS EXISTS
#
# "The adversary cannot influence which values get released" (robust
# declassification) rests on the workload being unable to enroll its own
# declassification key: if it could, it would sign its own tokens and release
# anything. The kernel's trusted-key set is written ONLY by
# `Kernel::set_trusted_keys`, called ONLY at kernel construction from the
# node-controlled `NUCLEUS_DECLASSIFY_TRUSTED_KEYS` env — never from a request
# handler, which is workload-reachable.
#
# That is a reachability property, and nothing but this gate checks it. The day
# someone calls `set_trusted_keys` from a handler (or any non-construction
# site), the workload gains a path to influence the trusted set and the
# robustness argument silently fails. This gate makes it loud: the only non-test
# callers allowed are the two kernel-construction sites.
#
# Usage: scripts/check-declassify-governor-keys-sealed.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

# The construction sites that legitimately provision the governor keys.
ALLOWED=(
  "crates/nucleus-tool-proxy/src/main.rs"   # HTTP-path kernel construction
  "crates/nucleus-tool-proxy/src/mcp.rs"    # MCP-path kernel construction
)

is_allowed() {
  local f="$1"
  for a in "${ALLOWED[@]}"; do [ "$f" = "$a" ] && return 0; done
  return 1
}

violations=""
# A CALL is `.set_trusted_keys(` (leading dot, open paren) — this excludes the
# doc-comment references (`[`set_trusted_keys`]`, `via set_trusted_keys`).
while IFS= read -r f; do
  # Test code may configure trusted keys freely — it is not workload-reachable.
  case "$f" in
    */tests/*|tests/*|*_tests.rs) continue ;;
  esac
  is_allowed "$f" && continue
  violations+="$f"$'\n'
done < <(git grep -l -e '\.set_trusted_keys(' -- '*.rs' 2>/dev/null || true)

if [ -n "$violations" ]; then
  echo "FAIL a non-construction caller of Kernel::set_trusted_keys exists:"
  echo "$violations" | sed '/^$/d;s/^/       /'
  echo ""
  echo "    set_trusted_keys writes the declassification trusted-key set. It must"
  echo "    be called ONLY at kernel construction, from node-controlled env — never"
  echo "    from a request handler, which the workload can reach. A handler that"
  echo "    reaches it lets the workload influence which values may be released,"
  echo "    breaking robust declassification. Provision the keys at construction"
  echo "    (main.rs / mcp.rs) instead, or add the new construction site to the"
  echo "    allowlist in this gate with a note on why it is not workload-reachable."
  exit 1
fi

echo "ok  Kernel::set_trusted_keys has no non-test caller outside the two kernel"
echo "    construction sites — the governor trusted-key set is not workload-writable."
