#!/usr/bin/env bash
# InputsAuthorized "no-unwitnessed-ingest" gate — RATCHET (brick 4).
#
# Brick 3 (#2042) content-addressed every agent-INPUT ingest: each site now
# records the SHA-256 of the ACTUAL ingested bytes on its FlowTracker node via
# the hashing variants `observe_with_content_hash` /
# `observe_with_label_and_content_hash`, or through the ingest chokepoint helpers
# `observe_flow` / `http_observe_flow` (which hash internally). This gate LOCKS
# that: it FAILS the build if a NON-hashing FlowTracker observe that could create
# an un-witnessed INGEST node reappears on the agent path — the structural defeat
# of the McpToolResult laundering channel (an ingest node with no content hash is
# a node whose bytes were never witnessed, so a poisoned tool result could be
# laundered back in un-attested).
#
# The gate flags the NON-hashing observe variants — bare `.observe(`,
# `.observe_with_label(`, `.observe_with_parents(` — in the agent-path scope,
# UNLESS the exact trimmed snippet is listed in scripts/ingest-hashed-allowlist.txt.
# The hashing variants (`observe_with_content_hash`,
# `observe_with_label_and_content_hash`) and the `_with_parents_and_hash` inner
# helper are NOT matched (the `_content_hash` / `_and_hash` suffix defeats the
# pattern), so a correctly-hashed ingest never trips.
#
# Allowlist = the legitimate NON-INGEST observe sites (F13 classification):
# OutboundAction egress markers, the portcullis-effects NucleusRuntime observes
# on the type-level discharge path (where the `Labeled<_,Integrity,Conf>` return
# type + `DischargedBundle` proof — not the content hash — is the enforcement),
# ceiling-propagation sentinels, and the kernel operation-causal marker. Each
# entry carries a comment naming its NodeKind and why it is not an input ingest.
# The list only shrinks; any NEW un-allowlisted bare ingest observe fails.
#
# Scope = the agent ingest path: the MCP tool proxy (the McpToolResult laundering
# channel this brick locks), the standalone MCP server/guard, and the
# portcullis-effects runtime where file/web bytes enter the causal DAG.
# `#[cfg(test)]` blocks and comment lines are stripped.
#
# Usage: scripts/check-ingest-hashed.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

ALLOWLIST="scripts/ingest-hashed-allowlist.txt"

# In-scope = the agent ingest path. Every agent-INPUT ingest here MUST record the
# content hash of the bytes it observed (Brick 3), via a hashing observe variant
# or an ingest chokepoint helper. portcullis-effects is IN scope for THIS gate
# (unlike the mediation gate) because the NucleusRuntime is where file/web bytes
# enter the FlowTracker; its non-ingest observes are allowlisted below.
SCOPE_DIRS=(crates/nucleus/src crates/nucleus-tool-proxy/src \
            crates/nucleus-mcp/src crates/nucleus-mcp-guard/src \
            crates/portcullis-effects/src)

# The NON-hashing observe variants (bare / label / parents). The hashing variants
# `observe_with_content_hash` and `observe_with_label_and_content_hash`, and the
# `observe_with_parents_and_hash` inner helper, are NOT matched: their suffix
# means the required `(` does not immediately follow the captured method name.
PATTERN='\.observe(_with_label|_with_parents)?[[:space:]]*\('

# Load allowlist: non-empty, non-comment lines are literal TRIMMED code snippets
# permitted to hold a non-hashing observe (each a justified NON-INGEST site).
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
# block) that matches the non-hashing observe pattern. Brace-balanced cfg(test)
# stripping; skip comment lines.
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
        # skip — clear pending so it does not swallow the next braced item
        # (latent false-NEGATIVE; fix shared with scripts/check-mediation.sh).
        if (line ~ /;/) { pending=0 }
    }
    stripped=line; sub(/^[[:space:]]+/,"",stripped)
    if (stripped ~ /^\/\//) { next }
    # Non-hashing observe variant (bare / label / parents), never a hashing one.
    if (line ~ /\.observe(_with_label|_with_parents)?[[:space:]]*\(/) {
        printf "%s:%d:%s\n", FILENAME, FNR, line
    }
}
AWK

# Drop test-only sources. As well as the `/(tests|benches)/` integration dirs
# (mediation-gate convention), exclude src-level whole-file test modules pulled
# in via `#[cfg(test)] mod ...;` — e.g. `tests_main.rs`, `*_tests.rs` — whose
# `#[cfg(test)]` lives on the OUTER `mod` line, so the in-file AWK stripper never
# sees it. Codebase naming convention: `tests_<x>.rs`, `<x>_tests.rs`.
list_files() {
    if command -v rg >/dev/null 2>&1; then
        rg -l --glob '*.rs' -e "$PATTERN" "${SCOPE_DIRS[@]}"
    else
        grep -rlE --include='*.rs' "$PATTERN" "${SCOPE_DIRS[@]}"
    fi | grep -vE '/(tests|benches)/|/tests?_[^/]*\.rs$|_tests?\.rs$' || true
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
    done < <(awk "$AWK_PROG" "$f")
done < <(list_files)

if [[ "${#hits[@]}" -gt 0 ]]; then
    echo "ingest-hash gate FAILED: non-hashing FlowTracker observe (possible un-witnessed ingest) on the agent path:" >&2
    printf '  %s\n' "${hits[@]}" >&2
    echo >&2
    echo "Fix: content-address the ingested bytes. Record the SHA-256 of the ACTUAL bytes on the node via" >&2
    echo "observe_with_content_hash / observe_with_label_and_content_hash, or route through the ingest" >&2
    echo "chokepoint helpers (observe_flow / http_observe_flow, which hash internally)." >&2
    echo "If this observe is a legitimate NON-INGEST site (it observes no incoming bytes), add the exact" >&2
    echo "trimmed line to $ALLOWLIST with a comment naming its NodeKind and why it is not an input ingest." >&2
    exit 1
fi

echo "ingest-hash gate PASSED: no un-allowlisted non-hashing ingest observe on the agent path."
