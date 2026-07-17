#!/usr/bin/env bash
# North Star mediation gate — BACKSTOP (brick 0: process spawn).
#
# The nucleus effect boundary is proof-carrying admission: a consequential agent
# effect is obtained through `portcullis_core::discharge` (`preflight_action` ->
# `DischargedBundle`) and enforced at the type level in `portcullis-effects`
# (an un-preflighted effect is a compile error). This gate is the BACKSTOP for
# the raw-primitive escape: it FAILS the build if an AGENT-PATH crate constructs
# a raw process-spawn primitive (`Command::new` / `tokio::process::Command::new`)
# that bypasses the discharge-gated effect API, unless the exact call is listed
# in scripts/mediation-allowlist.txt.
#
# The allowlist is BASELINE DEBT that only shrinks: every entry is an un-migrated
# agent-path spawn to be moved behind the discharge-gated effect API. The gate
# forbids any NEW un-allowlisted agent-path spawn, so the count can only ratchet
# down as sites migrate.
#
# Scope = the agent effect path ONLY. NOT host/operator/infra crates
# (nucleus-cli, -node, -guest-init, xtask, -sdk, -client — operator/host
# authority, outside the agent threat model) and NOT portcullis-effects (the
# sealed home). `#[cfg(test)]` blocks and comment lines are stripped.
#
# Usage: scripts/check-mediation.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

ALLOWLIST="scripts/mediation-allowlist.txt"

# In-scope = the agent effect path. Effects here MUST go through
# `preflight_action` -> `DischargedBundle`, never a raw primitive.
SCOPE_DIRS=(crates/nucleus/src crates/nucleus-tool-proxy/src \
            crates/nucleus-mcp/src crates/nucleus-mcp-guard/src)

# Raw process-spawn primitive (brick 0). Later bricks add net/fs patterns.
PATTERN='Command::new'

# Load allowlist: non-empty, non-comment lines are literal TRIMMED code snippets
# permitted to construct a raw spawn (baseline debt to migrate).
allow_snippets=()
if [[ -f "$ALLOWLIST" ]]; then
    while IFS= read -r line; do
        trimmed="${line#"${line%%[![:space:]]*}"}"
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
        [[ -z "$trimmed" ]] && continue
        [[ "$trimmed" == \#* ]] && continue
        allow_snippets+=("$trimmed")
    done < "$ALLOWLIST"
fi

# AWK: emit `path:lineno:code` for each production line (outside any #[cfg(test)]
# block) that matches PATTERN. Brace-balanced cfg(test) stripping; skip comments.
read -r -d '' AWK_PROG <<'AWK' || true
BEGIN { skip=0; brace=0; pending=0 }
{
    line=$0
    tmp=line; no=gsub(/\{/,"{",tmp)
    tmp=line; nc=gsub(/\}/,"}",tmp)
    if (skip==1) { brace += no - nc; if (brace <= 0) { skip=0; brace=0 } next }
    if (line ~ /#\[cfg\(test\)\]/) { pending=1; next }
    if (pending==1) {
        if (no>0) {                       # block body starts on this line
            skip=1; brace = no - nc; pending=0
            if (brace <= 0) { skip=0; brace=0 }
            next
        }
        # cfg(test) on a non-block item (`mod tests;`, `use ...;`): no block to
        # skip — clear pending so it does not swallow the next braced item.
        if (line ~ /;/) { pending=0 }
    }
    stripped=line; sub(/^[[:space:]]+/,"",stripped)
    if (stripped ~ /^\/\//) { next }
    if (line ~ PAT) { printf "%s:%d:%s\n", FILENAME, FNR, line }
}
AWK

list_files() {
    if command -v rg >/dev/null 2>&1; then
        rg -l --glob '*.rs' "$PATTERN" "${SCOPE_DIRS[@]}"
    else
        grep -rl --include='*.rs' "$PATTERN" "${SCOPE_DIRS[@]}"
    fi | grep -vE '/(tests|benches)/' || true
}

hits=()
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    while IFS= read -r rec; do
        [[ -z "$rec" ]] && continue
        code="${rec#*:*:}"
        trimmed="${code#"${code%%[![:space:]]*}"}"
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
        allowed=0
        if [[ "${#allow_snippets[@]}" -gt 0 ]]; then
            for snip in "${allow_snippets[@]}"; do
                [[ "$trimmed" == "$snip" ]] && { allowed=1; break; }
            done
        fi
        [[ "$allowed" -eq 1 ]] && continue
        hits+=("$rec")
    done < <(awk -v PAT="$PATTERN" "$AWK_PROG" "$f")
done < <(list_files)

if [[ "${#hits[@]}" -gt 0 ]]; then
    echo "mediation gate FAILED: raw process spawn on the agent path, outside the discharge-gated effect API:" >&2
    printf '  %s\n' "${hits[@]}" >&2
    echo >&2
    echo "Fix: obtain the effect through portcullis_core::discharge (preflight_action -> DischargedBundle)" >&2
    echo "via portcullis-effects, not a raw Command::new. If this is legitimate un-migrated baseline debt," >&2
    echo "add the exact trimmed line to $ALLOWLIST (which only shrinks as sites migrate)." >&2
    exit 1
fi

echo "mediation gate PASSED: no un-allowlisted raw process spawn on the agent path."
