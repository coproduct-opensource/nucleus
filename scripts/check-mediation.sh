#!/usr/bin/env bash
# North Star mediation gate — BACKSTOP (brick 0: process spawn; brick B5: net egress).
#
# The nucleus effect boundary is proof-carrying admission: a consequential agent
# effect is obtained through `portcullis_core::discharge` (`preflight_action` ->
# `DischargedBundle`) and enforced at the type level in `portcullis-effects`
# (an un-preflighted effect is a compile error). This gate is the BACKSTOP for
# the raw-primitive escape: it FAILS the build if an AGENT-PATH crate constructs
# a raw effect primitive that bypasses the discharge-gated effect API, unless the
# exact call is allowlisted.
#
# TWO patterns are enforced:
#   * SPAWN — `Command::new` / `tokio::process::Command::new`. Allowlist:
#     scripts/mediation-allowlist.txt (BASELINE DEBT that only shrinks; every
#     entry is an un-migrated agent-path spawn to move behind the effect API).
#   * NET   — a raw reqwest agent egress (`.send()`). An agent web_fetch /
#     web_search must go through the sealed `NetEffect::fetch` in
#     portcullis-effects (minted `DischargedBundle`), never a raw
#     `web_client…send()`. Allowlist: scripts/mediation-net-allowlist.txt
#     (INFRA egress by-file / by-line — operator/host authority, no agent
#     session/token — NOT shrinking debt). Because infra and agent reqwest both
#     use reqwest, the NET allowlist is a by-file (node_client.rs) plus by-line
#     (audit S3 / webhook) exemption; after relocation the only `.send()` left on
#     the agent path is infra.
#
# Scope = the agent effect path ONLY. NOT host/operator/infra crates
# (nucleus-cli, -node, -guest-init, xtask, -sdk, -client — operator/host
# authority, outside the agent threat model) and NOT portcullis-effects (the
# sealed home — where the relocated raw `Command::new` / reqwest `.send()` now
# legitimately live). `#[cfg(test)]` blocks and comment lines are stripped.
#
# Usage: scripts/check-mediation.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

SPAWN_ALLOWLIST="scripts/mediation-allowlist.txt"
NET_ALLOWLIST="scripts/mediation-net-allowlist.txt"

# In-scope = the agent effect path. Effects here MUST go through
# `preflight_action` -> `DischargedBundle`, never a raw primitive.
#
# nucleus-mcp-guard is DELIBERATELY EXCLUDED (brick B4): it is an operator-run
# CLI guard whose one process spawn (proxy.rs `run_stdio_proxy`) launches the
# downstream MCP server named on the guard's OWN command line — `cmd` is
# operator/CLI-provided, never agent-controlled — so it is infra, not an agent
# effect, and has no agent session/token to mint a `DischargedBundle` against.
# RE-SCOPE IT (add the dir back here) if mcp-guard ever spawns a process from an
# agent-controlled value.
SCOPE_DIRS=(crates/nucleus/src crates/nucleus-tool-proxy/src \
            crates/nucleus-mcp/src)

# AWK: emit `path:lineno:code` for each production line (outside any #[cfg(test)]
# block) that contains the literal PAT. Brace-balanced cfg(test) stripping; skip
# comment lines. Literal (index-based) match so PAT needs no regex escaping.
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
    if (index(line, PAT) > 0) { printf "%s:%d:%s\n", FILENAME, FNR, line }
}
AWK

# Loaded per-pattern by load_allowlist:
allow_snippets=()   # exact TRIMMED-line snippets permitted to carry the primitive
allow_files=()      # whole-file exemptions (repo-relative paths)

load_allowlist() {
    local f="$1" line trimmed
    allow_snippets=()
    allow_files=()
    [[ -f "$f" ]] || return 0
    while IFS= read -r line; do
        trimmed="${line#"${line%%[![:space:]]*}"}"
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
        [[ -z "$trimmed" ]] && continue
        [[ "$trimmed" == \#* ]] && continue
        if [[ "$trimmed" == file:* ]]; then
            allow_files+=("${trimmed#file:}")
        else
            allow_snippets+=("$trimmed")
        fi
    done < "$f"
}

# List in-scope .rs files containing the literal PAT, excluding tests/benches
# directories (never the agent runtime path).
list_files() {
    local pat="$1"
    if command -v rg >/dev/null 2>&1; then
        rg -l -F --glob '*.rs' "$pat" "${SCOPE_DIRS[@]}"
    else
        grep -rlF --include='*.rs' "$pat" "${SCOPE_DIRS[@]}"
    fi | grep -vE '/(tests|benches)/' || true
}

# Run one pattern; sets the global FAILED on any un-allowlisted hit.
run_pattern() {
    local pat="$1" label="$2" allowfile="$3"
    load_allowlist "$allowfile"

    local hits=() f rec code trimmed snip af allowed
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        # Whole-file infra exemption.
        allowed=0
        for af in "${allow_files[@]:-}"; do
            [[ -z "$af" ]] && continue
            if [[ "$f" == "$af" || "$f" == */"$af" ]]; then allowed=1; break; fi
        done
        [[ "$allowed" -eq 1 ]] && continue

        while IFS= read -r rec; do
            [[ -z "$rec" ]] && continue
            code="${rec#*:*:}"
            trimmed="${code#"${code%%[![:space:]]*}"}"
            trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
            allowed=0
            for snip in "${allow_snippets[@]:-}"; do
                [[ -z "$snip" ]] && continue
                [[ "$trimmed" == "$snip" ]] && { allowed=1; break; }
            done
            [[ "$allowed" -eq 1 ]] && continue
            hits+=("$rec")
        done < <(awk -v PAT="$pat" "$AWK_PROG" "$f")
    done < <(list_files "$pat")

    if [[ "${#hits[@]}" -gt 0 ]]; then
        echo "mediation gate FAILED ($label): raw effect primitive on the agent path, outside the discharge-gated effect API:" >&2
        printf '  %s\n' "${hits[@]}" >&2
        echo >&2
        FAILED=1
        return 0
    fi
    echo "mediation gate PASSED ($label): no un-allowlisted hit on the agent path."
}

FAILED=0
run_pattern 'Command::new' 'spawn' "$SPAWN_ALLOWLIST"
# `.send()` with EMPTY parens is the reqwest `RequestBuilder::send()` egress
# signature; channel/other sends carry a message argument (`.send(msg)`) and are
# not matched, so the net pattern isolates HTTP egress without false positives.
run_pattern '.send()' 'net' "$NET_ALLOWLIST"

if [[ "$FAILED" -ne 0 ]]; then
    echo >&2
    echo "Fix: obtain the effect through portcullis_core::discharge (preflight_action -> DischargedBundle)" >&2
    echo "via portcullis-effects (spawn -> ShellEffect::run_argv[_async]; net -> NetEffect::fetch), not a" >&2
    echo "raw Command::new / reqwest .send(. If this is legitimate un-migrated baseline debt (spawn) or an" >&2
    echo "infra sink (net), add it to the matching allowlist (spawn debt only shrinks; net infra is by-file/by-line)." >&2
    exit 1
fi

echo "mediation gate PASSED: no un-allowlisted raw effect primitive on the agent path (spawn + net)."
