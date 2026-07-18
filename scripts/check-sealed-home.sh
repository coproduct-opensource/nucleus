#!/usr/bin/env bash
# North Star sealed-home INTEGRITY gate (terminal-push B7).
#
# The migration relocated every raw agent-path effect primitive OUT of the agent
# crates and INTO the single sealed home `RealEffects` in portcullis-effects,
# where it is legitimate because the sealed fn is reached only PAST a minted
# `DischargedBundle` (`_proof: &DischargedBundle`) and the `PolicyEnforced` gate.
# The mediation gate (check-mediation.sh) proves the agent crates are CLEAN; it
# DELIBERATELY EXCLUDES portcullis-effects (the sealed home is where raw
# primitives are allowed to live). This gate is the COMPLEMENT: it guards the
# sealed home itself, so the relocation did not silently open a NEW hole.
#
# Invariant: inside `crates/portcullis-effects/src`, a raw effect primitive may
# appear ONLY on the exact known sealed-home lines (the allowlist). A NEW raw
# primitive anywhere else in portcullis-effects — a free helper fn, a new method,
# a second reqwest sink — is an UN-GATED leak (it bypasses the `_proof` gate that
# only the sealed `RealEffects::{run_argv, run_argv_async, fetch}` fns carry) and
# FAILS the build. The allowlist only shrinks or holds; it never grows without a
# reviewer consciously blessing a new sealed-home line.
#
# TWO patterns are enforced (mirrors check-mediation.sh exactly):
#   * SPAWN — the literal `Command::new`. This subsumes BOTH the sync
#     `std::process::Command::new` and the async `tokio::process::Command::new`
#     (both contain the substring `Command::new`); the bare
#     `Fn(&mut tokio::process::Command)` harden-hook type signatures do NOT
#     contain `Command::new`, so they never match.
#   * NET   — the reqwest `RequestBuilder::send()` egress (`.send()` with EMPTY
#     parens). Channel/other sends carry a message argument (`.send(msg)`) and are
#     not matched.
#
# Scope = the sealed home ONLY: `crates/portcullis-effects/src`. `#[cfg(test)]`
# blocks and comment lines are stripped (brace-balanced cfg(test) AWK, literal
# index match — identical to check-mediation.sh).
#
# Allowlist = scripts/sealed-home-allowlist.txt: the exact TRIMMED source lines
# of the known sealed-home raw primitives inside `impl … for RealEffects`
# (the crate's sole I/O-capable, externally-unconstructable type). See that file
# for the per-line site map.
#
# Usage: scripts/check-sealed-home.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

ALLOWLIST="scripts/sealed-home-allowlist.txt"

# In-scope = the sealed home. A raw effect primitive here is legitimate ONLY on
# an allowlisted RealEffects sealed-home line; anywhere else it is an un-gated
# leak that bypasses the `_proof` gate.
SCOPE_DIRS=(crates/portcullis-effects/src)

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
# directories (never the sealed runtime path).
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
        # Whole-file exemption (unused by default — the sealed home is scanned
        # in full; kept for structural parity with check-mediation.sh).
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
        echo "sealed-home gate FAILED ($label): raw effect primitive in portcullis-effects OUTSIDE the sealed RealEffects home:" >&2
        printf '  %s\n' "${hits[@]}" >&2
        echo >&2
        FAILED=1
        return 0
    fi
    echo "sealed-home gate PASSED ($label): every raw primitive is on a known sealed-home line."
}

FAILED=0
run_pattern 'Command::new' 'spawn' "$ALLOWLIST"
# `.send()` with EMPTY parens is the reqwest `RequestBuilder::send()` egress
# signature; channel/other sends carry a message argument (`.send(msg)`) and are
# not matched, so the net pattern isolates HTTP egress without false positives.
run_pattern '.send()' 'net' "$ALLOWLIST"

if [[ "$FAILED" -ne 0 ]]; then
    echo >&2
    echo "Fix: a raw effect primitive may live in portcullis-effects ONLY inside the sealed" >&2
    echo "RealEffects home (run_argv / run_argv_async / fetch — reached past a minted" >&2
    echo "&DischargedBundle and the PolicyEnforced gate). A NEW raw Command::new / reqwest" >&2
    echo ".send() elsewhere in the crate is an un-gated leak. Either route it through an" >&2
    echo "existing sealed fn, or (if it is a genuine new sealed-home line) add the exact" >&2
    echo "TRIMMED line to scripts/sealed-home-allowlist.txt with a site-map comment." >&2
    exit 1
fi

echo "sealed-home gate PASSED: no raw effect primitive outside the sealed RealEffects home (spawn + net)."
